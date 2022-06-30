
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

		self.key = None # Our RSA key as an object
		self.session_id = None # The first exchange hash H generated

		# If the message reading loop is running. On client disconnect,
		#  the loop method should end.
		self.running = threading.Event()

		# Handles key exchange, algorithm setting up
		self.algorithm_handler = AlgorithmHandler()

		# Handles channels
		self.channel_handler = ChannelHandler()

		# All values used for an open channel
		# self.client_channel = None
		# self.server_channel = None
		# self.term_using_pixels = False
		# self.term_width = None
		# self.term_height = None
		# self.term_width_pixels = None
		# self.term_height_pixels = None
		# self.term_environ = {}

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

		# Start our message handler to send/receive messages
		self.message_handler = MessageHandler(conn)


	def loop(self):
		self.running.set()
		while self.running:
			msg = self.message_handler.recv()
			if msg is None: # If no packet
				# Just exit for now. This should be handled by polling.
				return 
			self.handle_message(msg)


	def handle_message(self, msg):
		if isinstance(msg, messages.SSH_MSG_KEXINIT):
			self.handle_SSH_MSG_KEXINIT(msg)

		elif isinstance(msg, messages.SSH_MSG_KEX_ECDH_INIT):
			self.handle_SSH_MSG_KEX_ECDH_INIT(msg)

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

		elif isinstance(msg, messages.SSH_MSG_CHANNEL_DATA):
			self.handle_SSH_MSG_CHANNEL_DATA(msg)

		elif isinstance(msg, messages.SSH_MSG_CHANNEL_CLOSE):
			self.handle_SSH_MSG_CHANNEL_CLOSE(msg)

		elif isinstance(msg, messages.SSH_MSG_DISCONNECT):
			self.handle_SSH_MSG_DISCONNECT(msg)

		else: # Unhandled message instance
			self.running = False
			print(f"UNHANDLED MESSAGE {msg}")
			return


	def handle_SSH_MSG_KEXINIT(self, msg): # SSH-TRANS
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


	def handle_SSH_MSG_KEX_ECDH_INIT(self, msg): # SSH-TRANS
		# Handle the clients KEX_ECDH_INIT to generate our shared secret
		#  and let the client know we've done so
		server_kex_ecdh_reply = self.algorithm_handler.handle_client_KEX_ECDH_INIT(msg)
		self.message_handler.send(server_kex_ecdh_reply)

		# Set up all the algorithms that are going to be used and let
		#  the client know we are ready to start using them
		self.algorithm_handler.setup_algorithms()
		resp = messages.SSH_MSG_NEWKEYS()
		self.message_handler.send(resp)


	def handle_SSH_MSG_NEWKEYS(self, msg): # SSH-TRANS
		# Enable all our set algorithms in the message handler
		self.algorithm_handler.enable_algorithms(self.message_handler)


	def handle_SSH_MSG_SERVICE_REQUEST(self, msg): # SSH-TRANS
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


	def handle_SSH_MSG_USERAUTH_REQUEST(self, msg): # SSH-USERAUTH
		# Retrieve our banner and sent to user
		banner = self.auth_handler.get_banner()
		self.message_handler.send(banner)

		# Handle the request
		resp = self.auth_handler.handle_USERAUTH_REQUEST(msg)
		self.message_handler.send(resp)


	# TODO: For channel requests, check if authenticated first
	...


	def handle_SSH_MSG_CHANNEL_OPEN(self, msg): # SSH-CONNECT
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
			resp = self.channel_handler.handle_CHANNEL_OPEN(msg, self.running, self.message_handler)
			self.message_handler.send(resp)


	def handle_SSH_MSG_CHANNEL_REQUEST(self, msg): # SSH-CONNECT
		# NOTE: A channel will not be opened unless the user is
		#  authenticated (see handle_SSH_MSG_CHANNEL_OPEN), so no need
		#  to check authentication again.

		resp = self.channel_handler.handle_CHANNEL_REQUEST(msg)
		self.message_handler.send(resp)
		return


	def handle_SSH_MSG_CHANNEL_DATA(self, msg):
		self.channel_handler.handle_CHANNEL_DATA(msg)


	def handle_SSH_MSG_CHANNEL_CLOSE(self, msg):
		self.channel_handler.handle_CHANNEL_CLOSE(msg)

	def handle_SSH_MSG_DISCONNECT(self, msg):
		# End the running loop
		self.running.clear()

		# Also close any currently running channels
		... # TODO
