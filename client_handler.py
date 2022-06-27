
import messages
from algorithms import AlgorithmHandler, NoMatchingAlgorithm
from config import Config
from data_types import DataWriter
from message_handler import MessageHandler


# Debug helper functions. Take an instance of a client handler
def print_terminal_size(ch):
	if ch.term_using_pixels:
		print(f"Terminal size: width={ch.term_width_pixels}px, height={ch.term_height_pixels}px")
	else:
		print(f"Terminal size: width={ch.term_width}, height={ch.term_height}")
def print_terminal_environment(ch):
	print(f"Terminal environment: {ch.term_environ}")



class ClientHandler:

	def __init__(self, conn):
		self.key = None # Our RSA key as an object
		self.session_id = None # The first exchange hash H generated

		# All values we need access to
		self.algorithm_handler = AlgorithmHandler()
		# self.V_C = None # Client's identification string
		# self.V_S = None # Server's identification string
		# self.I_C = None # The payload of the client's SSH_MSG_KEXINIT
		# self.I_S = None # The payload of the server's SSH_MSG_KEXINIT
		# self.K_S = None # The host key. Blob of self.key
		# self.e = None # The exchange value sent by the client
		# self.f = None # The exchange value sent by the server
		# self.K = None # The shared secret

		# All values used during and after user authentication
		self.auth_required = Config.AUTH_REQUIRED
		self.available_user_names = {"user"}
		self.user_name = None # Current username set during user auth
		self.available_service_names = {"ssh-connection"}
		self.service_name = None # current service name set during user auth
		self.available_authentications = {"password"}
		self.successful_authentications = set() # Set during userauth requests
		self.is_authenticated = False

		# All values used for an open channel
		self.client_channel = None
		self.server_channel = None
		self.term_using_pixels = False
		self.term_width = None
		self.term_height = None
		self.term_width_pixels = None
		self.term_height_pixels = None
		self.term_environ = {}

		####################
		# SETUP CONNECTION #
		####################
		# Exchange identification strings
		V_C = conn.recv(255)
		V_S = Config.IDENTIFICATION_STRING.encode("utf-8")
		for banner_line in Config.IDENTIFICATION_BANNER:
			conn.send(banner_line.encode("utf-8") + b"\r\n")
		conn.send(V_S + b"\r\n")

		# Save the exchange strings in algorithm handler
		self.algorithm_handler.set_exchange_strings(V_C, V_S)

		# If the message reading loop is running. On client disconnect,
		#  the loop method should end.
		self.running = False

		# Start our message handler to send/receive messages
		self.message_handler = MessageHandler(conn)


	def loop(self):
		self.running = True
		while self.running:
			msg = self.message_handler.recv()
			if msg is None: # If no packet
				# Just exit for now. This should be handled by polling.
				print("No data recv")
				return 
			self.handle_message(msg)


	def handle_message(self, msg):
		if isinstance(msg, messages.SSH_MSG_KEXINIT):
			self.handle_SSH_MSG_KEXINIT(msg)

		elif isinstance(msg, messages.SSH_MSG_KEXDH_INIT):
			self.handle_SSH_MSG_KEXDH_INIT(msg)

		elif isinstance(msg, messages.SSH_MSG_NEWKEYS):
			self.handle_SSH_MSG_NEWKEYS(msg)

		elif isinstance(msg, messages.SSH_MSG_SERVICE_REQUEST):
			self.handle_SSH_MSG_SERVICE_REQUEST(msg)

		elif isinstance(msg, messages.SSH_MSG_USERAUTH_REQUEST):
			self.handle_SSH_MSG_USERAUTH_REQUEST(msg)

		elif isinstance(msg, messages.SSH_MSG_CHANNEL_OPEN):
			self.handle_SSH_MSG_CHANNEL_OPEN(msg)

		elif isinstance(msg, messages.SSH_MSG_CHANNEL_REQUEST):
			self.handle_SSH_MSG_CHANNEL_REQUEST(msg)

		else: # Unhandled message instance
			self.running = False
			print(f"UNHANDLED MESSAGE {msg}")
			return


	def handle_SSH_MSG_KEXINIT(self, msg):
		# Generate our own KEXINIT and send
		server_kexinit = self.algorithm_handler.generate_server_kexinit(
			languages_client_to_server=[],
			languages_server_to_client=[],
			first_kex_packet_follows=False)
		self.message_handler.send(server_kexinit)

		# Handle the client's KEXINIT to find matches
		try:
			self.algorithm_handler.handle_client_KEXINIT(msg)
		except NoMatchingAlgorithm:
			self.running = False
			return


	def handle_SSH_MSG_KEXDH_INIT(self, msg):
		# Handle the clients KEXDH_INIT to generate our shared secret
		#  and let the client know we've done so
		server_kexdh_reply = self.algorithm_handler.handle_client_KEXDH_INIT(msg)
		self.message_handler.send(server_kexdh_reply)

		# Set up all the algorithms that are going to be used and let
		#  the client know we are ready to start using them
		self.algorithm_handler.setup_algorithms()
		resp = messages.SSH_MSG_NEWKEYS()
		self.message_handler.send(resp)


	def handle_SSH_MSG_NEWKEYS(self, msg):
		# Enable all our set algorithms in the message handler
		self.algorithm_handler.enable_algorithms(self.message_handler)


	def handle_SSH_MSG_SERVICE_REQUEST(self, msg):
		service_name = msg.service_name

		if service_name == "ssh-userauth":
			# We can handle this!
			resp = messages.SSH_MSG_SERVICE_ACCEPT(service_name)
			self.message_handler.send(resp)

		# TODO: Handle ssh-connection

		else:
			error_msg = f"Service '{service_name}' is not available."
			print(f" [*] {error_msg}")
			resp = messages.SSH_MSG_DISCONNECT.SERVICE_NOT_AVAILABLE(error_msg)
			self.message_handler.send(resp)
			self.running = False


	def handle_SSH_MSG_USERAUTH_REQUEST(self, msg):
		# Send a banner message.
		banner = messages.SSH_MSG_USERAUTH_BANNER(message=Config.USERAUTH_BANNER)
		self.message_handler.send(banner)

		user_name = msg.user_name
		service_name = msg.service_name
		method_name = msg.method_name

		# SSH-USERAUTH, 5.

		# TODO: The user_name and service_name MAY change. These MUST
		#  be checked, and MUST flush any authentication states if
		#  they change. If it is unable to flush, it MUST disconnect
		#  if the user_name or service_name change.
		if user_name != self.user_name or service_name != self.service_name:
			self.successful_authentications.clear()
		self.user_name = user_name
		self.service_name = service_name

		# TODO: If the requested service is not available, the server
		#  MAY disconnect immediately or at any later time. Sending a
		#  proper disconnect message is RECOMMENDED. In any case, if the
		#  service does not exist, authentication MUST NOT be accepted.
		if service_name not in self.available_service_names:
			error_msg = f"Service '{service_name}' is not available."
			print(f" [*] {error_msg}")
			resp = messages.SSH_MSG_DISCONNECT.SERVICE_NOT_AVAILABLE(error_msg)
			self.message_handler.send(resp)
			self.running = False
			return

		# TODO: If the requested user name does not exist, the server
		#  MAY disconnect, or MAY send a bogus list of acceptable
		#  authentication method name values, but never accept any.
		#  This makes it possible for the server to avoid disclosing
		#  information on which accounts exist. In any case, if the
		#  user name does not exist, the authentication request MUST
		#  NOT be accepted.
		if user_name not in self.available_user_names:
			error_msg = f"Username '{user_name}' is not available."
			print(f" [*] {error_msg}")
			resp = messages.SSH_MSG_DISCONNECT.ILLEGAL_USER_NAME(error_msg)
			self.message_handler.send(resp)
			self.running = False
			return

		# Other available authentications that can be used to log in
		remaining_auths = list(self.available_authentications.difference(self.successful_authentications))

		# SSH-USERAUTH, 7.
		if method_name == "publickey":
			# TODO: Write this
			...
			# msg.authenticating
			# msg.algorithm_name
			# msg.key_blob
			# msg.public_key
			# msg.signature
			raise Exception("TODO PUBLIC KEY")

		# SSH-USERAUTH, 8.
		elif method_name == "password":
			changing_password = msg.changing_password
			password = msg.password
			
			# Wrong password
			if password != Config.PASSWORD:
				resp = messages.SSH_MSG_USERAUTH_FAILURE(
					available_authentications=remaining_auths,
					partial_success=False)
				self.message_handler.send(resp)
				return

			# Setting a new password
			if changing_password:
				# TODO: Handle this for real? Do we want to allow users
				#  to do this in the first place?
				# TODO: Send a message if the new password is invalid?
				new_password = msg.new_password

			# Successful login!
			resp = messages.SSH_MSG_USERAUTH_SUCCESS()
			self.message_handler.send(resp)

		# SSH-USERAUTH, 9.
		elif method_name == "hostbased":
			# TODO: Write this
			...
			# msg.algorithm_name
			# msg.certificates
			# msg.host_name
			# msg.client_user_name
			# msg.signature
			raise Exception("TODO PUBLIC KEY")

		# SSH-USERAUTH, 5.2.
		elif method_name == "none":
			# MUST always reject, unless the client is to be granted
			#  access without any authentication, in which case, the
			#  server MUST accept this request. The main purpose of
			#  sending this request is to get the list of supported
			#  methods from the server.
			if self.auth_required:
				self.successful_authentications.add(method_name)
				resp = messages.SSH_MSG_USERAUTH_FAILURE(
					available_authentications=remaining_auths,
					partial_success=True)
				self.message_handler.send(resp)
			else:
				self.is_authenticated = True
				resp = messages.SSH_MSG_USERAUTH_SUCCESS()
				self.message_handler.send(resp)

		# Unhandled authentication method
		else:
			resp = messages.SSH_MSG_USERAUTH_FAILURE(
				available_authentications=remaining_auths,
				partial_success=False)
			self.message_handler.send(resp)


	# TODO: For channel requests, check if authenticated first
	...


	def handle_SSH_MSG_CHANNEL_OPEN(self, msg):
		channel_type = msg.channel_type
		client_channel = msg.sender_channel
		initial_window_size = msg.initial_window_size
		maximum_packet_size = msg.maximum_packet_size

		# The channel_type is a name with similar extension mechanisms.
		#  The client_channel is a local identifier for the channel used
		#  by the sender of this message. The initial_window_size
		#  specifies how many bytes of channel data can be sent to the
		#  sender of this message without adjusting the window. The
		#  maximum_packet_size specifies the maximum size of an
		#  individual data packet that can be sent to the sender. For
		#  example, one might want to use smaller packets for
		#  interactive connections to get better interactive response on
		#  slow links.
		print(f"{channel_type=}")
		print(f"{client_channel=}")
		print(f"{initial_window_size=}")
		print(f"{maximum_packet_size=}")

		# We decide whether we can open the channel, and respond with
		#  either SSH_MSG_CHANNEL_OPEN_CONFIRMATION or
		#  SSH_MSG_CHANNEL_OPEN_FAILURE.
		...

		# TODO: Handle multiple channels per connection
		if self.client_channel is not None or self.server_channel is not None:
			error_msg = f"Resource shortage. Can only handle one channel per user"
			print(f" [*] {error_msg}")
			resp = messages.SSH_MSG_CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE(client_channel, error_msg)
			self.message_handler.send(resp)

		# SSH-CONNECT 6.1.
		if channel_type == "session":

			# recipient_channel is the channel number given in the original
			#  open request, and client_channel is the channel number
			#  allocated by the server.
			self.client_channel = client_channel
			self.server_channel = 420

			# TODO: Calculate the actual window size and packet sizes
			...

			resp = messages.SSH_MSG_CHANNEL_OPEN_CONFIRMATION(
				recipient_channel=self.client_channel,
				sender_channel=self.server_channel,
				initial_window_size=1048576,
				maximum_packet_size=16384) # TODO: Add channel type specific data
			self.message_handler.send(resp)

		# SSH-CONNECT 6.3.2.
		elif channel_type == "x11":
			# DO NOT handle x11. This is hard :(
			error_msg = f"Administratively prohibited"
			print(f" [*] {error_msg}")
			resp = messages.SSH_MSG_CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED(client_channel, error_msg)
			self.message_handler.send(resp)

		# SSH-CONNECT 7.2.
		elif channel_type == "forwarded-tcpip":
			# DO NOT handle forwarded-tcpip. This is hard :(
			error_msg = f"Administratively prohibited"
			print(f" [*] {error_msg}")
			resp = messages.SSH_MSG_CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED(client_channel, error_msg)
			self.message_handler.send(resp)

		# SSH-CONNECT 7.2.
		elif channel_type == "direct-tcpip":
			# DO NOT handle direct-tcpip. This is hard :(
			error_msg = f"Administratively prohibited"
			print(f" [*] {error_msg}")
			resp = messages.SSH_MSG_CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED(client_channel, error_msg)
			self.message_handler.send(resp)

		# Unhandled channel type
		else:
			error_msg = f"Unknown channel type"
			print(f" [*] {error_msg}")
			resp = messages.SSH_MSG_CHANNEL_OPEN_FAILURE.UNKNOWN_CHANNEL_TYPE(client_channel, error_msg)
			self.message_handler.send(resp)

		return
		# TODO: Find cases where connect can just fail.
		error_msg = f"Connect failed"
		print(f" [*] {error_msg}")
		resp = messages.SSH_MSG_CHANNEL_OPEN_FAILURE.CONNECT_FAILED(client_channel, error_msg)
		self.message_handler.send(resp)


	# TODO: For channel requests etc, check if channel numbers are good
	...


	def handle_SSH_MSG_CHANNEL_REQUEST(self, msg):
		recipient_channel = msg.recipient_channel
		request_type = msg.request_type
		want_reply = msg.want_reply

		print(f"{request_type=}")

		# SSH-CONNECT 6.2.
		if request_type == "pty-req":
			term_environment_var = msg.term_environment_var
			term_width = msg.term_width
			term_height = msg.term_height
			term_width_pixels = msg.term_width_pixels
			term_height_pixels = msg.term_height_pixels
			terminal_modes = msg.terminal_modes
			
			# The encoded terminal modes are described in SSH-CONNECT 8.
			# TODO: Handle terminal modes
			print(f"{terminal_modes=}") #its a blob
			...

			# Character/row dimensions override the pixel dimensions
			#  when non-zero
			if term_width != 0 and term_height != 0:
				self.term_using_pixels = False
				self.term_width = term_width
				self.term_height = term_height
				self.term_width_pixels = None
				self.term_height_pixels = None
			elif term_width_pixels != 0 and term_height_pixels != 0:
				self.term_using_pixels = True
				self.term_width = None
				self.term_height = None
				self.term_width_pixels = term_width_pixels
				self.term_height_pixels = term_height_pixels
			else:
				if want_reply:
					resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
					self.message_handler.send(resp)

			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_SUCCESS(self.client_channel)
				self.message_handler.send(resp)

			# DEBUG: Print the new terminal size. Remove when done
			print_terminal_size(self)

		# SSH-CONNECT 6.3.1.
		elif request_type == "x11-req":
			# DO NOT handle forwarded-tcpip. This is hard :(
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
				self.message_handler.send(resp)

		# SSH-CONNECT 6.4.
		elif request_type == "env":
			name = msg.name
			value = msg.value
			print("environ name is", name)
			print("environ value is", value)
			self.term_environ[name] = value
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_SUCCESS(self.client_channel)
				self.message_handler.send(resp)

			# DEBUG: Print the terminal environment. Remove when done
			print_terminal_environment(self)
		
		# SSH-CONNECT 6.5.
		elif request_type == "shell":
			# This message will request that the user's default shell
			#  (typically defined in /etc/passwd in UNIX systems) be
			#  started at the other end.
			print("TODO SHELL")
			
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_SUCCESS(self.client_channel)
				self.message_handler.send(resp)
		
		# SSH-CONNECT 6.5.
		elif request_type == "exec":
			# This message will request taht the server start the
			#  execution of the given command. The 'command' string may
			#  contain a path. Normal precautions MUST be taken to
			#  prevent the execution of unauthorized commands.

			# DO NOT handle exec. This is hard :(
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
				self.message_handler.send(resp)

		# SSH-CONNECT 6.5.
		elif request_type == "subsystem":
			# This last form executes a predefined subsystem. It is
			#  expected that these will include a general file transfer
			#  mechanism, and possibly other features. Implementations
			#  may also allow configuring more such mechanisms. As the
			#  user's shell is usually used to execute the subsystem, it
			#  is advisable for the subsystem protocol to have a "magic
			#  cookie" at the beginning of the protocol transaction to
			#  distinguish it from arbitrary output generated by shell
			#  initialization scripts, etc. This spurious output from
			#  the shell may be filtered out either at the server or at
			#  the client.

			# DO NOT handle subsystem. This is hard :(
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
				self.message_handler.send(resp)

		# SSH-CONNECT 6.7.
		elif request_type == "window-change":
			term_width = msg.term_width
			term_height = msg.term_height
			term_width_pixels = msg.term_width_pixels
			term_height_pixels = msg.term_height_pixels

			# Character/row dimensions override the pixel dimensions
			#  when non-zero
			if term_width != 0 and term_height != 0:
				self.term_using_pixels = False
				self.term_width = term_width
				self.term_height = term_height
				self.term_width_pixels = None
				self.term_height_pixels = None
			elif term_width_pixels != 0 and term_height_pixels != 0:
				self.term_using_pixels = True
				self.term_width = None
				self.term_height = None
				self.term_width_pixels = term_width_pixels
				self.term_height_pixels = term_height_pixels
			else:
				if want_reply:
					resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
					self.message_handler.send(resp)

			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_SUCCESS(self.client_channel)
				self.message_handler.send(resp)

			# DEBUG: Print the new terminal size. Remove when done
			print_terminal_size(self)

		# SSH-CONNECT 6.8.
		elif request_type == "xon-xoff":
			# DO NOT handle xon-xoff. This is hard :(
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
				self.message_handler.send(resp)

		# SSH-CONNECT 6.9.
		elif request_type == "signal":
			# DO NOT handle signal. This is hard :(
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
				self.message_handler.send(resp)

		# SSH-CONNECT 6.10.
		elif request_type == "exit-status":
			# DO NOT handle exit-status. This is hard :(
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
				self.message_handler.send(resp)

		# SSH-CONNECT 6.11.
		elif request_type == "exit-signal":
			# DO NOT handle exit-signal. This is hard :(
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
				self.message_handler.send(resp)

		# Unhandled request type
		else:
			if want_reply:
				resp = messages.SSH_MSG_CHANNEL_FAILURE(self.client_channel)
				self.message_handler.send(resp)
