import time
from os import urandom as os_urandom

from diffie_hellman_handler import DiffieHellmanHandler
from public_key_handler import PublicKeyHandler
from packet import PacketHandler
from ssh_msg import *


class ProtocolHandler:

	def __init__(self, conn, addr, login_manager):
		self.conn = conn
		self.addr = addr
		self.login_manager = login_manager

		self.packet_handler = PacketHandler()
		self.dh_handler = DiffieHellmanHandler()
		self.public_key_handler = PublicKeyHandler("ssh-rsa")
		self.public_key_handler.read_key("CustomSSH.priv")

		# Protocol versions
		self.server_protocol = {
			"protoversion": "2.0",
			"extra_lines": [
				# "oh yea",
				# "oh yea",
				# "i guess i'm really"
			],
			"softwareversion": "Bimpson4.20",
			"comment": "yea"}
		self.client_protocol = {}
		self.I_C = None
		self.I_S = None

		self.running = False


	def protocol_string_exchange(self):
		extra_lines = []

		line = b""
		while True:

			# Read until we get a CR LF
			while not line.endswith(b"\r\n"):
				line += self.conn.recv(1)

			# If it starts with "SSH-", it's the user's protocol
			if line.startswith(b"SSH-"):
				break

			# If not, it's an extra line
			extra_lines.append(line.decode("utf-8").rstrip("\r\n"))
			line = b""

		# Handle the protocol line
		protocol_line = line.decode("utf-8").rstrip("\r\n")
		protocol, _, comment = protocol_line.partition(" ")
		_, protoversion, softwareversion = protocol.split("-")
		
		# Save the user's protocol
		self.client_protocol = {
			"protoversion": protoversion,
			"extra_lines": extra_lines,
			"softwareversion": softwareversion,
			"comment": comment
		}

		# Store client's identification string
		self.V_C = line.rstrip(b"\r\n") 

		# Send our protocol extra lines first
		for line in self.server_protocol.get("extra_lines", []):
			line = f"{line}\r\n"
			self.conn.sendall(line.encode("utf-8"))

		# And send our protocol
		server_protoversion = self.server_protocol["protoversion"]
		server_comment = self.server_protocol["comment"]
		server_softwareversion = self.server_protocol["softwareversion"]
		if not server_comment:
			line = f"SSH-{server_protoversion}-{server_softwareversion} {server_comment}\r\n"
		else:
			line = f"SSH-{server_protoversion}-{server_softwareversion}\r\n"
		line_b = line.encode("utf-8")

		# Store server's identification string
		self.V_S = line_b.rstrip(b"\r\n") 

		self.conn.sendall(line_b)


	def handle_next_packet(self):
		packet = self.packet_handler.read_packet_from_conn(self.conn)
		if packet is None:
			return False

		data = SSH_MSG.create_from_packet(packet)

		handler_method_name = f"{data.msg_type}_handler"
		handler = self.__getattribute__(handler_method_name)

		handler(data)
		return True # Did handle a packet


	def send_packet(self, msg):
		if isinstance(msg, SSH_MSG_DISCONNECT):
			print(f" [*] Disconnecting client: {msg.description}")
			data = msg.to_bytes()
			self.running = False # We expect the client to disconnect.
		if isinstance(msg, SSH_MSG):
			data = msg.to_bytes()
		else:
			data = msg

		packet = self.packet_handler.new_packet(data)

		# Send the packet!
		raw = packet.compile()
		self.conn.sendall(raw)


	def start(self):
		# First do the whole ass protocol exchange
		self.protocol_string_exchange()

		stop_when_unsuccessful_count = 3
		unsuccessful_count = 0

		# Then start the packet handling loop :)
		self.running = True
		while self.running:
			handled_a_packet = self.handle_next_packet()

			if not handled_a_packet:
				unsuccessful_count += 1
				print(f"Didn't receive a packet. ({unsuccessful_count})")

				if unsuccessful_count >= stop_when_unsuccessful_count:
					print("Disconnecting as we hit max unsuccessful count")

					disconnect_msg = SSH_MSG_DISCONNECT.CONNECTION_LOST(
						f"Didn't receive a packet for {stop_when_unsuccessful_count} tries.")
					self.send_packet(disconnect_msg)
					continue

				# Sleep until trying to handle next packet
				time.sleep(1)

			else:
				unsuccessful_count = 0


	def SSH_MSG_KEXINIT_handler(self, data):
		# Store client's KEXINIT message
		self.I_C = data.to_bytes()

		# TODO: Handle data
		...

		# Reply with our own SSH_MSG_KEXINIT.
		cookie = os_urandom(16)
		kex_algorithms = self.dh_handler.available_algorithms
		server_host_key_algorithms = self.public_key_handler.available_algorithms

		# Pull the enc/mac/comp algs from packet handler
		enc_algs = self.packet_handler.encryption_handler.available_algorithms
		mac_algs = self.packet_handler.mac_handler.available_algorithms
		com_algs = self.packet_handler.compression_handler.available_algorithms

		# Default with no languages, we don't need to specify
		languages = []

		# We never want to guess a kex packet
		first_kex_packet_follows = False

		# Construct the reply message and send it away
		reply_kexinit = SSH_MSG_KEXINIT(
			cookie=cookie,
			kex_algorithms=kex_algorithms,
			server_host_key_algorithms=server_host_key_algorithms,
			encryption_algorithms_client_to_server=enc_algs,
			encryption_algorithms_server_to_client=enc_algs,
			mac_algorithms_client_to_server=mac_algs,
			mac_algorithms_server_to_client=mac_algs,
			compression_algorithms_client_to_server=com_algs,
			compression_algorithms_server_to_client=com_algs,
			languages_client_to_server=languages,
			languages_server_to_client=languages,
			first_kex_packet_follows=first_kex_packet_follows)

		# Store server's KEXINIT message
		self.I_S = reply_kexinit.to_bytes()

		# Send reply
		self.send_packet(reply_kexinit)

		# Set and prepare new algorithms
		self.dh_handler.set_algorithm(kex_algorithms[0])
		self.packet_handler.prepare_algorithms(
			enc_c_to_s=enc_algs[0],
			enc_s_to_c=enc_algs[0],
			mac_c_to_s=mac_algs[0],
			mac_s_to_c=mac_algs[0],
			com_c_to_s=com_algs[0],
			com_s_to_c=com_algs[0])


	def SSH_MSG_KEXDH_INIT_handler(self, data):
		"""
		The following steps are used to exhange a key.  In this, C is the
		client; S is the server; p is a large safe prime; g is a generator
		for a subgroup of GF(p); q is the order of the subgroup; V_S is S's
		identification string; V_C is C's identification string; K_s is S's
		public host key; I_C is C's SSH_MSG_KEXINIT message and I_S is S's
		SSH_MSG_KEXINIT message that have been exchanged before this part
		begins.

		1. C generates a random number x (1 < x < q) and computes
		   e = g^x mod p.  C sends e to S.

		2. S generates a random number y (0 < y < q) and computes
		   f = g^y mod p.  S receives e.  It computes K = e^y mod p,
		   H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
		   (these elements are encoded according to their types; see below),
		   and signature s on H with its private host key.  S sends
		   (K_S || f || s) to C.  The signing operation may involve a
		   second hashing operation.

		3. C verifies that K_S really is the host key for S (e.g., using
		   certificates or a local database).  C is also allowed to accept
		   the key without verification; however, doing so will render the
		   protocol insecure against active attacks (but may be desirable for
		   practical reasons in the short term in many environments).  C then
		   computes K = f^x mod p, H = hash(V_C || V_S || I_C || I_S || K_S
		   || e || f || K), and verifies the signature s on H.

		Values of 'e' or 'f' that are not in the range [1, p-1] MUST NOT be
		sent or accepted by either side.  If this condition is violated, the
		key exchagne fails.
		"""

		# Retrieve user's e
		e = data.e
		self.dh_handler.set_client_public_key(e)

		f = self.dh_handler.gen_server_public_key()
		K = self.dh_handler.gen_shared_key()

		V_C = self.V_C
		V_S = self.V_S
		I_C = self.I_C
		I_S = self.I_S
		K_S = self.public_key_handler.key_b

		# Calculate H and it's signature
		H = self.dh_handler.generate_H(V_C, V_S, I_C, I_S, K_S)
		H_sig = self.public_key_handler.sign(H)

		# Construct a SSH_MSG_KEXDH_REPLY
		reply = SSH_MSG_KEXDH_REPLY(
			K_S=K_S,
			f=f,
			H_sig=H_sig)
		self.send_packet(reply)

		# Send a new keys too.
		reply = SSH_MSG_NEWKEYS()
		self.send_packet(reply)
		self.sent_NEWKEYS = True


	def SSH_MSG_NEWKEYS_handler(self, data):
		if not self.sent_NEWKEYS:
			# Reply with our own.
			reply = SSH_MSG_NEWKEYS()
			self.send_packet(reply)

		# Set prepared algorithms
		self.packet_handler.set_prepared_algorithms()

		# Set keys and IVs
		self.dh_handler.generate_keys()
		self.packet_handler.set_keys(
			iv_c_to_s=self.dh_handler.initial_iv_c_to_s,
			iv_s_to_c=self.dh_handler.initial_iv_s_to_c,
			enc_c_to_s=self.dh_handler.enc_key_c_to_s,
			enc_s_to_c=self.dh_handler.enc_key_s_to_c,
			mac_c_to_s=self.dh_handler.mac_key_c_to_s,
			mac_s_to_c=self.dh_handler.mac_key_s_to_c)

		self.sent_NEWKEYS = False


	def SSH_MSG_SERVICE_REQUEST_handler(self, data):
		service_name = data.service_name

		if service_name == "ssh-userauth":
			reply = SSH_MSG_SERVICE_ACCEPT(service_name)
			self.send_packet(reply)

		elif service_name == "ssh-connection":
			reply = SSH_MSG_SERVICE_ACCEPT(service_name)
			self.send_packet(reply)

		else:
			# A service that isn't handled
			reply = SSH_MSG_DISCONNECT.SERVICE_NOT_AVAILABLE(
				f"Service {service_name} is not available.")
			self.send_packet(reply)


	def SSH_MSG_USERAUTH_REQUEST_handler(self, data):
		session, reply = self.login_manager.handle_userauth_request(data)
		print("session is", session)
		print("reply is", reply)
		self.session = session
		self.send_packet(reply)
		return


		print("Method name is", data.method_name)
		method_name = data.method_name

		# TODO: Move most of this to a handler.
		# auths = ["publickey", "password", "hostbased"]
		auths = ["password"]

		if method_name == "publickey":
			print("TODO")

		elif method_name == "password":
			username = data.user_name
			password = data.password
			# TODO: Check password
			print("Password is", password)
			if password != "bingus":
				reply = SSH_MSG_USERAUTH_FAILURE(
					auths=auths, partial_success=False)
				self.send_packet(reply)
				return

			print("awesome gamer")

		elif method_name == "hostbased":
			print("TODO")

		elif method_name == "none":
			reply = SSH_MSG_USERAUTH_FAILURE(
				auths=auths, partial_success=False)
			self.send_packet(reply)

		else:
			print(" [!] Cannot handle that method")
			reply = SSH_MSG_USERAUTH_FAILURE()
