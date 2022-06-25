
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

		# TODO: Handle ssh-userauth
		# TODO: Handle ssh-connection

		# Unhandled service name
		error_msg = f"Service {service_name} is not available."
		print(f" [*] {error_msg}")
		resp = messages.SSH_MSG_DISCONNECT.SERVICE_NOT_AVAILABLE(error_msg)
		self.message_handler.send(resp)
