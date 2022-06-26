
import binascii
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from os import urandom

import messages
from config import Config
from data_types import DataWriter
from message_handler import MessageHandler


class ClientHandler:

	def __init__(self, conn):
		self.key = None # Our RSA key as an object
		self.session_id = None # The first exchange hash H generated

		# All values we need access to
		self.V_C = None # Client's identification string
		self.V_S = None # Server's identification string
		self.I_C = None # The payload of the client's SSH_MSG_KEXINIT
		self.I_S = None # The payload of the server's SSH_MSG_KEXINIT
		self.K_S = None # The host key. Blob of self.key
		self.e = None # The exchange value sent by the client
		self.f = None # The exchange value sent by the server
		self.K = None # The shared secret

		# All values used during and after user authentication
		self.auth_required = True
		self.available_user_names = {"user"}
		self.user_name = None # Current username set during user auth
		self.available_service_names = {"ssh-connection"}
		self.service_name = None # current service name set during user auth
		self.available_authentications = {"password"}
		self.successful_authentications = set() # Set during userauth requests
		self.is_authenticated = False

		# Exchange identification strings and save them
		self.V_C = conn.recv(255).strip(b"\r\n")
		self.V_S = Config.IDENTIFICATION_STRING.encode("utf-8")
		for banner_line in Config.IDENTIFICATION_BANNER:
			conn.send(banner_line.encode("utf-8") + b"\r\n")
		conn.send(self.V_S + b"\r\n")

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

		else: # Unhandled message instance
			self.running = False
			print(f"UNHANDLED MESSAGE {msg}")
			return


	def handle_SSH_MSG_KEXINIT(self, msg):
		# Store the client's SSH_MSG_KEXINIT payload
		self.I_C = msg.payload()

		# Respond with our available algorithms
		cookie = urandom(16)
		resp = messages.SSH_MSG_KEXINIT(
			cookie=cookie,
			kex_algorithms=["diffie-hellman-group14-sha1"],
			server_host_key_algorithms=["ssh-rsa"],
			encryption_algorithms_client_to_server=["aes128-cbc"],
			encryption_algorithms_server_to_client=["aes128-cbc"],
			mac_algorithms_client_to_server=["hmac-sha1"],
			mac_algorithms_server_to_client=["hmac-sha1"],
			compression_algorithms_client_to_server=["none"],
			compression_algorithms_server_to_client=["none"],
			languages_client_to_server=[],
			languages_server_to_client=[],
			first_kex_packet_follows=False
		)
		self.I_S = resp.payload()
		self.message_handler.send(resp)

		# Check if our algorithms match
		...


	def handle_SSH_MSG_KEXDH_INIT(self, msg):
		# Store the client's exchange value
		self.e = msg.e

		# Generate our own key pair, and calculate the shared secret
		# diffie-hellman-group14-sha1
		self.y = int(binascii.hexlify(urandom(32)), base=16)
		self.f = pow(Config.GENERATOR, self.y, Config.PRIME) # g^y % p
		self.K = pow(self.e, self.y, Config.PRIME) # e^y % p

		# Retrieve our host key, and also save as a blob
		with open(Config.RSA_KEY) as f:
			self.key = RSA.import_key(f.read())
		w = DataWriter() # SSH-TRANS 6.6.
		w.write_string("ssh-rsa")
		w.write_mpint(self.key.e)
		w.write_mpint(self.key.n)
		self.K_S = w.data

		# Generate our exchange hash H
		HASH = lambda x: SHA1.new(x) # diffie-hellman-group14-sha1
		w = DataWriter() # SSH-TRANS 8.
		w.write_string(self.V_C)
		w.write_string(self.V_S)
		w.write_string(self.I_C)
		w.write_string(self.I_S)
		w.write_string(self.K_S)
		w.write_mpint(self.e)
		w.write_mpint(self.f)
		w.write_mpint(self.K)
		# diffie-hellman-group14-sha1
		H = HASH(w.data).digest() # exchange hash

		# The exchange hash H from the first key exchange is used as the
		#  session identifier.
		if self.session_id is None:
			self.session_id = H

		# Calculate the signature of H
		# SSH_RSA (pkcs1_15), diffie-hellman-group14-sha1
		# The signature algorithm MUST be applied over H, not original data.
		sig = pkcs1_15.new(self.key).sign(SHA1.new(H))
		w = DataWriter() # SSH-TRANS 6.6.
		w.write_string("ssh-rsa")
		w.write_uint32(len(sig))
		w.write_byte(sig)
		H_sig = w.data

		# Respond with our key exchange reply
		resp = messages.SSH_MSG_KEXDH_REPLY(
			K_S=self.K_S,
			f=self.f,
			H_sig=H_sig
		)
		self.message_handler.send(resp)

		# Set up our algorithms for the message hander
		self.message_handler.setup_keys(HASH, self.K, H, self.session_id)

		# Send out NEWKEYS message specifying we are ready to use our new
		#  keys!
		resp = messages.SSH_MSG_NEWKEYS()
		self.message_handler.send(resp)


	def handle_SSH_MSG_NEWKEYS(self, msg):
		# Start encrypting all packets and checking integrity
		self.message_handler.enable_encryption()
		self.message_handler.enable_integrity()


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


	def handle_SSH_MSG_CHANNEL_OPEN(self, msg):
		print("TODO: Handle", msg)
