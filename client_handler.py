
import threading

import messages
from algorithms import AlgorithmHandler, NoMatchingAlgorithm
from channels import ChannelHandler
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

	def __init__(self, conn, auth_handler):
		self.auth_handler = auth_handler

		# If the message reading loop is running. On client disconnect,
		#  the loop method should end.
		self.running = False

		# Handles key exchange, algorithm setting up
		self.algorithm_handler = AlgorithmHandler()

		# Handles channels
		self.channel_handler = ChannelHandler()

		# Exchange our protocol versions
		self.initialise_connection(conn)
		

	def initialise_connection(self, conn):
		# Exchange identification strings
		V_C = conn.recv(255)
		V_S = Config.IDENTIFICATION_STRING.encode("utf-8")
		for banner_line in Config.IDENTIFICATION_BANNER:
			conn.send(banner_line.encode("utf-8") + b"\r\n")
		conn.send(V_S + b"\r\n")

		# Save the exchange strings in algorithm handler
		self.algorithm_handler.set_exchange_strings(V_C, V_S)

		# Start our message handler to send/receive messages
		self.message_handler = MessageHandler(conn)


	def start(self):
		self.running = True
		while self.running:
			msg = self.message_handler.recv()

			# If the client disconnects from an invalid mac or anything,
			#  they will not send a MSG_DISCONNECT and just drop conn.
			if msg is None:
				self.stop()
				return

			self.handle_message(msg)


	def stop(self):
		# End the running loop
		self.running = False

		# Also close any currently running channels
		self.channel_handler.close_all_channels()


	def handle_message(self, msg):
		# SSH-TRANS
		if   isinstance(msg, messages.SSH_MSG_DISCONNECT):      self.handle_SSH_MSG_DISCONNECT(msg)
		elif isinstance(msg, messages.SSH_MSG_IGNORE):          self.handle_SSH_MSG_IGNORE(msg)
		elif isinstance(msg, messages.SSH_MSG_UNIMPLEMENTED):   self.handle_SSH_MSG_UNIMPLEMENTED(msg)
		elif isinstance(msg, messages.SSH_MSG_DEBUG):           self.handle_SSH_MSG_DEBUG(msg)
		elif isinstance(msg, messages.SSH_MSG_SERVICE_REQUEST): self.handle_SSH_MSG_SERVICE_REQUEST(msg)
		elif isinstance(msg, messages.SSH_MSG_SERVICE_ACCEPT):  self.handle_SSH_MSG_SERVICE_ACCEPT(msg)
		elif isinstance(msg, messages.SSH_MSG_KEXINIT):         self.handle_SSH_MSG_KEXINIT(msg)
		elif isinstance(msg, messages.SSH_MSG_KEX_ECDH_INIT):   self.handle_SSH_MSG_KEX_ECDH_INIT(msg)
		elif isinstance(msg, messages.SSH_MSG_KEX_ECDH_REPLY):  self.handle_SSH_MSG_KEX_ECDH_REPLY(msg)
		elif isinstance(msg, messages.SSH_MSG_NEWKEYS):         self.handle_SSH_MSG_NEWKEYS(msg)

		# SSH-USERAUTH
		elif isinstance(msg, messages.SSH_MSG_USERAUTH_REQUEST): self.handle_SSH_MSG_USERAUTH_REQUEST(msg)
		elif isinstance(msg, messages.SSH_MSG_USERAUTH_FAILURE): self.handle_SSH_MSG_USERAUTH_FAILURE(msg)
		elif isinstance(msg, messages.SSH_MSG_USERAUTH_SUCCESS): self.handle_SSH_MSG_USERAUTH_SUCCESS(msg)
		elif isinstance(msg, messages.SSH_MSG_USERAUTH_BANNER):  self.handle_SSH_MSG_USERAUTH_BANNER(msg)

		# SSH-CONNECT
		elif isinstance(msg, messages.SSH_MSG_GLOBAL_REQUEST):            self.handle_SSH_MSG_GLOBAL_REQUEST(msg)
		elif isinstance(msg, messages.SSH_MSG_REQUEST_SUCCESS):           self.handle_SSH_MSG_REQUEST_SUCCESS(msg)
		elif isinstance(msg, messages.SSH_MSG_REQUEST_FAILURE):           self.handle_SSH_MSG_REQUEST_FAILURE(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_OPEN):              self.handle_SSH_MSG_CHANNEL_OPEN(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_OPEN_CONFIRMATION): self.handle_SSH_MSG_CHANNEL_OPEN_CONFIRMATION(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_OPEN_FAILURE):      self.handle_SSH_MSG_CHANNEL_OPEN_FAILURE(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_WINDOW_ADJUST):     self.handle_SSH_MSG_CHANNEL_WINDOW_ADJUST(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_DATA):              self.handle_SSH_MSG_CHANNEL_DATA(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_EXTENDED_DATA):     self.handle_SSH_MSG_CHANNEL_EXTENDED_DATA(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_EOF):               self.handle_SSH_MSG_CHANNEL_EOF(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_CLOSE):             self.handle_SSH_MSG_CHANNEL_CLOSE(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_REQUEST):           self.handle_SSH_MSG_CHANNEL_REQUEST(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_SUCCESS):           self.handle_SSH_MSG_CHANNEL_SUCCESS(msg)
		elif isinstance(msg, messages.SSH_MSG_CHANNEL_FAILURE):           self.handle_SSH_MSG_CHANNEL_FAILURE(msg)

		# Any other codes
		else:
			self.running = False # Stop running
			print(f"Received an unhandled message type: {msg}")


	####################
	# Message Handlers #
	####################
	def handle_SSH_MSG_DISCONNECT(self, msg): # SSH-TRANS 11.1.
		# Stop running this connection
		self.stop()


	def handle_SSH_MSG_IGNORE(self, msg): # SSH-TRANS 11.2.
		# All implementations MUST understand and ignore this message
		#  at any time. Typically used as an additional protection
		#  measure against advanced traffic analysis techniques.
		return


	def handle_SSH_MSG_UNIMPLEMENTED(self, msg): # SSH-TRANS 11.4.
		# If we ever get this as a response to a message, we disconnect
		#  as otherwise it's hard to try pick up where we were.
		print(f" [!] SSH_MSG_UNIMPLEMENTED received for seq:{msg.packet_sequence_number}")
		self.stop()


	def handle_SSH_MSG_DEBUG(self, msg): # SSH-TRANS 11.3.
		# This message is used to transmit information that may help
		#  debugging. If 'always_display' is TRUE, the message SHOULD
		#  be displayed. Otherwise, it SHOULD NOT be displayed unless
		#  debugging information has been explicitly requested.
		if msg.always_display:
			print(f"DEBUG: {msg.message}")


	def handle_SSH_MSG_SERVICE_REQUEST(self, msg): # SSH-TRANS 10.
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


	def handle_SSH_MSG_SERVICE_ACCEPT(self, msg): # SSH-TRANS 10.
		# We should never receive this as a server, so ignore
		print(" [?] Received a SSH_MSG_SERVICE_ACCEPT?")
		return


	def handle_SSH_MSG_KEXINIT(self, msg): # SSH-TRANS 7.1.
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


	def handle_SSH_MSG_KEX_ECDH_INIT(self, msg): # RFC5656 4.
		# Handle the clients KEX_ECDH_INIT to generate our shared secret
		#  and let the client know we've done so
		server_kex_ecdh_reply = self.algorithm_handler.handle_client_KEX_ECDH_INIT(msg)
		self.message_handler.send(server_kex_ecdh_reply)

		# Set up all the algorithms that are going to be used and let
		#  the client know we are ready to start using them
		self.algorithm_handler.setup_algorithms()
		resp = messages.SSH_MSG_NEWKEYS()
		self.message_handler.send(resp)


	def handle_SSH_MSG_KEX_ECDH_REPLY(self, msg): # RFC5656 4.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_KEX_ECDH_REPLY?")
		return


	def handle_SSH_MSG_NEWKEYS(self, msg): # SSH-TRANS 7.3.
		# Enable all our set algorithms in the message handler
		self.algorithm_handler.enable_algorithms(self.message_handler)


	def handle_SSH_MSG_USERAUTH_REQUEST(self, msg): # SSH-USERAUTH 5.
		# Retrieve our banner and sent to user
		banner = self.auth_handler.get_banner()
		self.message_handler.send(banner)

		# Handle the request
		resp = self.auth_handler.handle_USERAUTH_REQUEST(msg)
		self.message_handler.send(resp)


	def handle_SSH_MSG_USERAUTH_FAILURE(self, msg): # SSH-USERAUTH 5.1.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_USERAUTH_FAILURE?")
		return


	def handle_SSH_MSG_USERAUTH_SUCCESS(self, msg): # SSH-USERAUTH 5.1.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_USERAUTH_SUCCESS?")
		return


	def handle_SSH_MSG_USERAUTH_BANNER(self, msg): # SSH-USERAUTH 5.4.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_USERAUTH_BANNER?")
		return


	# TODO: Implement
	def handle_SSH_MSG_GLOBAL_REQUEST(self, msg): # SSH-CONNECT 4.
		print("TODO: Handle SSH_MSG_GLOBAL_REQUEST")


	def handle_SSH_MSG_REQUEST_SUCCESS(self, msg): # SSH-CONNECT 4.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_REQUEST_SUCCESS?")
		return


	def handle_SSH_MSG_REQUEST_FAILURE(self, msg): # SSH-CONNECT 4.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_REQUEST_FAILURE?")
		return


	def handle_SSH_MSG_CHANNEL_OPEN(self, msg): # SSH-CONNECT 5.1.
		# If the client is not logged in, automatically fail
		if not self.auth_handler.is_authenticated:
			error_msg = "Cannot open a channel if not logged in"
			print(" [*] Client tried to open a channel when not logged in")
			resp = messages.SSH_MSG_CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED(client_channel, error_msg)
			self.message_handler.send(resp)

		else:
			# Handle channel allocation
			# NOTE: Must pass the message handler to the channel so that
			#  data can be sent asynchronously!
			resp = self.channel_handler.handle_CHANNEL_OPEN(msg, self.message_handler)
			self.message_handler.send(resp)


	def handle_SSH_MSG_CHANNEL_OPEN_CONFIRMATION(self, msg): # SSH-CONNECT 5.1.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_CHANNEL_OPEN_CONFIRMATION?")
		return


	def handle_SSH_MSG_CHANNEL_OPEN_FAILURE(self, msg): # SSH-CONNECT 5.1.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_CHANNEL_OPEN_FAILURE?")
		return


	# TODO: Implement
	def handle_SSH_MSG_CHANNEL_WINDOW_ADJUST(self, msg): # SSH-CONNECT 5.2.
		print("TODO: Handle SSH_MSG_CHANNEL_WINDOW_ADJUST")


	def handle_SSH_MSG_CHANNEL_DATA(self, msg): # SSH-CONNECT 5.2.
		# Pass on to channel
		self.channel_handler.handle_CHANNEL_DATA(msg)


	def handle_SSH_MSG_CHANNEL_EXTENDED_DATA(self, msg): # SSH-CONNECT 5.2.
		# Pass on to channel
		self.channel_handler.handle_CHANNEL_EXTENDED_DATA(msg)


	def handle_SSH_MSG_CHANNEL_EOF(self, msg): # SSH-CONNECT 5.3.
		# Pass on to channel
		self.channel_handler.handle_CHANNEL_EOF(msg)


	def handle_SSH_MSG_CHANNEL_CLOSE(self, msg): # SSH-CONNECT 5.3.
		# Pass on to channel
		self.channel_handler.handle_CHANNEL_CLOSE(msg)


	def handle_SSH_MSG_CHANNEL_REQUEST(self, msg): # SSH-CONNECT 5.4.
		# NOTE: A channel will not be opened unless the user is
		#  authenticated (see handle_SSH_MSG_CHANNEL_OPEN), so no need
		#  to check authentication again.

		resp = self.channel_handler.handle_CHANNEL_REQUEST(msg)
		self.message_handler.send(resp)
		return


	def handle_SSH_MSG_CHANNEL_SUCCESS(self, msg): # SSH-CONNECT 5.4.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_CHANNEL_SUCCESS?")
		return


	def handle_SSH_MSG_CHANNEL_FAILURE(self, msg): # SSH-CONNECT 5.4.
		# We should never receive this as a server, so ignore
		print(" [?} Received a SSH_MSG_CHANNEL_FAILURE?")
		return
