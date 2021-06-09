import time
from os import urandom as os_urandom
from Crypto.PublicKey import RSA

from helpers import ReadHelper, WriteHelper
from diffie_hellman_handler import DiffieHellmanHandler
from public_key_handler import PublicKeyHandler
from packet import PacketHandler


class ProtocolHandler:

	def __init__(self, conn, addr):
		self.conn = conn
		self.addr = addr

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
		print("Trying to run handler", handler_method_name)
		handler = self.__getattribute__(handler_method_name)

		handler(data)
		return True # Did handle a packet


	def send_packet(self, msg):
		if not isinstance(msg, SSH_MSG):
			data = msg
		else:
			data = msg.to_bytes()

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
					self.running = False
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
			# TODO: Handle this service
			reply = SSH_MSG_DISCONNECT.SERVICE_NOT_AVAILABLE(
				f"Service {service_name} not implemented yet.")
			self.send_packet(reply)
			return

		elif service_name == "ssh-connection":
			# TODO: Handle this service
			reply = SSH_MSG_DISCONNECT.SERVICE_NOT_AVAILABLE(
				f"Service {service_name} not implemented yet.")
			self.send_packet(reply)
			return

		else:
			# A service that isn't handled
			reply = SSH_MSG_DISCONNECT.SERVICE_NOT_AVAILABLE(
				f"Service {service_name} is not available.")
			self.send_packet(reply)
			return


# TODO: Add method that just creates a msg rather than get_class
class SSH_MSG:
	msg = {}

	def __init__(self):
		...

	def __init_subclass__(cls):
		"""Used to add subclasses to the msg dict to look them up"""
		SSH_MSG.msg[cls.code] = cls

	@classmethod
	def create_from_packet(cls, packet):
		reader = ReadHelper(packet)

		cmd_code = reader.read_uint8()
		msg_class = cls.get_class(cmd_code)
		data = msg_class.create_from_reader(reader)

		return data

	@classmethod
	def get_class(cls, code):
		return cls.msg[code]

	@property
	def msg_type(self):
		return self.__class__.__name__

	@classmethod
	def create_from_reader(cls, reader):
		print(f"CLASS {cls} DOES NOT HAVE create_from_reader METHOD")
		return None

	def to_bytes(self):
		print(f"OBJECT {self} DOES NOT HAVE to_bytes METHOD")
		return None


# Transport layer generic messages (1 to 19)
class SSH_MSG_DISCONNECT(SSH_MSG):
	"""
	RFC4253, 11.1. Disconnection Message
		.
			byte	SSH_MSG_DISCONNECT
			uint32	reason code
			string	description in ISO-10646 UTF-8 encoding [RFC3629]
			string	language tag [RFC3066]

		This message causes immediate termination of the connection.  All
		implementations MUST be able to process this message; they SHOULD be
		able to send this message.

		The sender MUST NOT send or receive any data after this message, and
		the recipient MUST NOT accept any data after receiving this message.
		The Disconnection Message 'description' string gives a more specific
		explanation in a human-readable form.  The Disconnectio Mesasge
		'reason code' gives the reason in a more machine-readable format
		(suitable for localization), and can have the values as displayed in
		the table below.  Note that the decimal representation is displayed
		in this table for readability, but the values are actually uint32
		values.

			SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT		 1
			SSH_DISCONNECT_PROTOCOL_ERROR					 2
			SSH_DISCONNECT_KEY_EXCHANGE_FAILED				 3
			SSH_DISCONNECT_RESERVED							 4
			SSH_DISCONNECT_MAC_ERROR						 5
			SSH_DISCONNECT_COMPRESSION_ERROR				 6
			SSH_DISCONNECT_SERVICE_NOT_AVAILABLE			 7
			SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED	 8
			SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE			 9
			SSH_DISCONNECT_CONNECTION_LOST					10
			SSH_DISCONNECT_BY_APPLICATION					11
			SSH_DISCONNECT_TOO_MANY_CONNECTIONS				12
			SSH_DISCONNECT_AUTH_CANCELLED_BY_USER			13
			SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE	14
			SSH_DISCONNECT_ILLEGAL_USER_NAME				15

		If the 'description' string is displayed, the control character
		filtering discussed in [SSH-ARCH] should be used to avoid attacks by
		sending terminal control characters.

		Requests for assignments of new Disconnection Message 'reason code'
		values (and associated 'description' text) in the range of 0x00000010
		to 0xFDFFFFFF MUST be done through the IETF CONSENSUS method, as
		described in [RFC2434].  The Disconnection Message 'reason code'
		values in the range of 0xFE000000 through 0xFFFFFFFF are reserved for
		PRIVATE USE.  As noted, the actual instructions to the IANA are in
		[SSH-NUMBERS].
	"""
	code = 1

	HOST_NOT_ALLOWED_TO_CONNECT		= lambda d: SSH_MSG_DISCONNECT(1, d)
	PROTOCOL_ERROR					= lambda d: SSH_MSG_DISCONNECT(2, d)
	KEY_EXCHANGE_FAILED				= lambda d: SSH_MSG_DISCONNECT(3, d)
	RESERVED						= lambda d: SSH_MSG_DISCONNECT(4, d)
	MAC_ERROR						= lambda d: SSH_MSG_DISCONNECT(5, d)
	COMPRESSION_ERROR				= lambda d: SSH_MSG_DISCONNECT(6, d)
	SERVICE_NOT_AVAILABLE			= lambda d: SSH_MSG_DISCONNECT(7, d)
	PROTOCOL_VERSION_NOT_SUPPORTED	= lambda d: SSH_MSG_DISCONNECT(8, d)
	HOST_KEY_NOT_VERIFIABLE			= lambda d: SSH_MSG_DISCONNECT(9, d)
	CONNECTION_LOST					= lambda d: SSH_MSG_DISCONNECT(10, d)
	BY_APPLICATION					= lambda d: SSH_MSG_DISCONNECT(11, d)
	TOO_MANY_CONNECTIONS			= lambda d: SSH_MSG_DISCONNECT(12, d)
	AUTH_CANCELLED_BY_USER			= lambda d: SSH_MSG_DISCONNECT(13, d)
	NO_MORE_AUTH_METHODS_AVAILABLE	= lambda d: SSH_MSG_DISCONNECT(14, d)
	ILLEGAL_USER_NAME				= lambda d: SSH_MSG_DISCONNECT(15, d)

	# NOTE: Until I need to, I'll assume the langauge tag can just be blank
	def __init__(self, reason_code, description, language_tag=""):
		self.reason_code = reason_code
		self.description = description
		self.language_tag = language_tag

	@classmethod
	def create_from_reader(cls, reader):
		# Ensure reader is at 0
		reader.head = 0
		cmd = reader.read_uint8()
		if cmd != cls.code:
			raise Exception("Using wrong msg")

		reason_code = reader.read_uint32()
		description = reader.read_string(ascii=True)
		language_tag = reader.read_string()

		# Check we've read everything
		if reader.remaining != 0:
			remaining_b = reader.data[-reader.remaining:]
			raise Exception(f"Still had data to read in {reader}: {remaining_b}")

		return cls(
			reason_code=reason_code,
			description=description,
			language_tag=language_tag)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_uint32(self.reason_code)
		writer.write_string(self.description)
		writer.write_string(self.language_tag)
		return writer.data


class SSH_MSG_IGNORE(SSH_MSG):
	"""
	RFC4253, 11.2. Ignored Data Message
		.
			byte	SSH_MSG_IGNORE
			string	data

		All implementations MUST understand (and ignore) this message at any
		time (after receiving the identification string).  No implementation
		is required to send them.  This message can be used as an additional
		protection measure against advanced traffic analysis techniques.
	"""
	code = 2
	def __init__(self):
		...

class SSH_MSG_UNIMPLEMENTED(SSH_MSG):
	"""
	RFC4253, 11.4. Reserved Message
		An implementation MUST respond to all unrecogniszed messages with an
		SSH_MSG_UNIMPLEMENTED message in the order in which the messages were
		received.  Such messages MUST be otherwise ignored.  Later protocol
		versions may define other meanings for these message types.

			byte	SSH_MSG_UNIMPLEMENTED
			uint32	packet sequence number of rejected message
	"""
	code = 3
	def __init__(self):
		...

class SSH_MSG_DEBUG(SSH_MSG):
	"""
	RFC4253, 11.3. Debug Message
		.
			byte	SSH_MSG_DEBUG
			boolean	always_display
			string	message in ISO-10466 UTF-8 encoding [RFC3629]
			string  language tag [RFC3066]

		All implementations MUST understand this message, but they are
		allowed to ignore it.  This message is used to transmit information
		that may help debugging.  If 'always_display' is TRUE, the message
		SHOULD be displayed.  Otherwise, it SHOULD NOT be displayed unless
		debugging information has been explicitly requested by the user.

		The 'message' doesn't need to contain a newline.  It is, however,
		allowed to consist of multiple lines separated by CRLF (Carriage
		Return - Line Feed) pairs.

		If the 'message' string is displayed, the terminal control character
		filtering discussed in [SSH-ARCH] should be used to avoid attacks by
		sending terminal control characters.
	"""
	code = 4
	def __init__(self):
		...

class SSH_MSG_SERVICE_REQUEST(SSH_MSG):
	"""
	RFC4253, 10. Service Request
		After the key exchange, the client requests a service.  The service
		is identified by a name.  The format of names and procedures for
		defining new names are defined in [SSH-ARCH] and [SSH-NUMBERS].

		Currently, the following names have been reserved:

			ssh-userauth
			ssh-connection

		Similar local naming policy is applied to the service names, as is
		applied to the algorithm names.  A local service should use the
		PRIVATE USE syntax of "servicename@domain".

			byte	SSH_MSG_SERVICE_REQUEST
			string	service name

		If the server rejects the service request, it SHOULD send an
		appropriate SSH_MSG_DISCONNECT message and MUST disconnect.

		When the service starts, it may have access to the session identifier
		generated during the key exchange.

	Continues in SSH_MSG_SERVICE_ACCEPT
	"""
	code = 5
	def __init__(self, service_name):
		self.service_name = service_name

	@classmethod
	def create_from_reader(cls, reader):
		# Ensure reader is at 0
		reader.head = 0
		cmd = reader.read_uint8()
		if cmd != cls.code:
			raise Exception("Using wrong msg")

		service_name = reader.read_string(ascii=True)

		# Check we've read everything
		if reader.remaining != 0:
			remaining_b = reader.data[-reader.remaining:]
			raise Exception(f"Still had data to read in {reader}: {remaining_b}")

		return cls(
			service_name=service_name)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_string(self.service_name)
		return writer.data

class SSH_MSG_SERVICE_ACCEPT(SSH_MSG):
	"""
	Continues from SSH_MSG_SERVICE_REQUEST

		If the server supports the service (and permits the client to use
		it), it MUST respond with the following:

			byte	SSH_MSG_SERVICE_ACCEPT
			string  service name

		Message numbers used by services should be in the area reserved for
		them (see [SSH-ARCH] and [SSH-NUMBERS]).  The transport level will
		continue to process its own messages.

		Note that after a key exchange with implicit server authentication,
		the client MUST wait for a response to its service request message
		before sending any further data.
	"""
	code = 6
	def __init__(self):
		...


# Algorithm negotiation messages (20 to 29)
class SSH_MSG_KEXINIT(SSH_MSG):
	"""
	RFC4253, 7.1, Algoritm Negotiation
		Key exchange begins by each side sending the following packet:
			byte		SSH_MSG_KEXINIT
			byte[16]	cookie (random bytes)
			name-list	kex_algorithms
			name-list	server_host_key_algorithms
			name-list	encryption_algorithms_client_to_server
			name-list	encryption_algorithms_server_to_client
			name-list	mac_algorithms_client_to_server
			name-list	mac_algorithms_server_to_client
			name-list	compression_algorithms_client_to_server
			name-list	compression_algorithms_server_to_client
			name-list	languages_client_to_server
			name-list	languages_server_to_client
			boolean		first_kex_packet_follows
			uint32		0 (reserved for future extension)

		Each of the algorithm name-lists MUST be a comma-separated list of
		algorithm names (see Algorithm Naming in [SSH-ARCH] and additional
		information in [SSH-NUMBERS]).  Each supported (allowed) algorithm
		MUST be listed in order of preference, from most to least.

		The first algorithm in each name-list MUST be the preferred (guessed)
		algorithm.  Each name-list MUST contain at least one algorithm name.

			cookie
				The 'cookie' MUST be a random value generated by the sender.
				Its purpose is to make it impossible for either side to fully
				determine the keys and the session identifier.

			kex_algorithms
				Key exchange algorithms were defined above.  The first
				algorithm MUST be the preferred (and guessed) algorithm.  If
				both sides make the same guess, that algorithm MUST be used.
				Otherwise, the following algorithm MUST be used to choose a key
				exchange method: Iterate over client's kex algorithms, one at a
				time.  Choose the first algorithm that satisfies the following
				conditions:

				+  the server also supports the algorithm,

				+  if the algorithm requires an encryption-capable host key,
				   there is an encryption-capable algorithm on the server's
				   server_host_key_algorithms that is also supported by the
				   client, and

				+  if the algorithm requires a signature-capable host key,
				   there is a signature-capable algorithm on the server's
				   server_host_key_algorithms that is also supported by the
				   client.

			If no algorithm satisfying all these conditions can be found, the
			connection fails, and both sides MUST disconnect.

			server_host_key_algorithms
				A name-list of the algorithms supported for the server host
				key.  The server lists the algorithms for which it has host
				keys; the client lists the algorithms that it is willing to
				accept. There MAY be multiple host keys for a host, possibly
				with different algorithms.

				Some host keys may not support both signatures and encryption
				(this can be determined from the algorithm), and thus not all
				host keys are valid for all key exchange methods.

				Algorithm selection depends on whether the chosen key exchange
				algorithm requres a signature or an encryption-capable host
				key.  It MUST be possible to determine this from the public key
				algorithm name.  The first algorithm on the client's name-list
				that satisfies the requirements and is also supported by the
				server MUST be chosen.  If there is no such algorithm, both
				sides MUST disconnect.

			encryption_algorithms
				A name-list of acceptable symmetric encryption algorithms (also
				known as ciphers) in order of preference.  The chosen
				encryption algorithm to each direction MUST be the first
				algorithm on the client's name-list that is also on the
				server's name-list.  If there is no such algorithm, both sides
				MUST disconnect.

				Note that "none" must be explicitly listed if it is to be
				acceptable.  The defined algorithm names are listed in Section
				6.3.

			mac_algorithms
				A name-list of acceptable MAC algorithms in order of
				preference.  The chosen MAC algorithm MUST be the first
				algorithm on the client's name-list that is also on the
				server's name-list.  If there is no such algorithm, both sides
				MUST disconnect.

				Note that "none" must be explicitly listed if it is to be
				acceptable.  The MAC algorithm names are listed in Section 6.4.

			compression_algorithms
				A name-list of acceptable compression algorithms in order of
				preference.  The chosen compression algorithm MUST be the first
				algorithm on the client's name-list that is also on the
				server's name-list.  If there is no such algorithm, both sides
				MUST disconnect.

				NOTE that "none" must be explicitly listed if it is to be
				acceptable.  The compression algorithm names are listed in
				Section 6.2.

			languages
				This is a name-list of language tags in order of preference
				[RFC3066].  Both parties MAY ignore this name-list.  If there
				are no language preferences, this name-list SHOULD be empty as
				defined in Section 5 of [SSH-ARCH].  Language tags SHOULD NOT
				be present unless they are known to be needed by the sending
				party.

			first_kex_packet_follows
				Indicates whether a guessed key exchange packet follows.  If a
				guessed packet will be sent, this MUST be TRUE.  If no guessed
				packet will be sent, this MUST be FALSE.

				After receiving the SSH_MSG_KEXINIT packet from the other side,
				each party will know whether their guess was right.  If the
				other party's guess was wrong, and this field was TRUE, the
				next packet MUST be silently ignored, and both sides MUST then
				act as determined by the negotiated key exchange method.  If
				the guess was right, key exchange MUST continue using the
				guessed packet.

		After the SSH_MSG_KEXINIT message exchange, the key exchange
		algorithm is run.  It may involve several packet exchanges, as
		specified by the key exchange method.

		Once a party has sent a SSH_MSG_KEXINIT message for key exchange or
		re-exchange, until it has sent a SSH_MSG_NEWKEYS message (Section
		7.3), it MUST NOT send any messages other than:

		o  Transport layer generic messages (1 to 19) (but
		   SSH_MSG_SERVICE_REQUEST and SSH_MSG_SERVICE_ACCEPT MUST NOT be
		   sent);

		o  Algorithm negotiation messages (20 to 29) (but further
		   SSH_MSG_KEXINIT messages MUST NOT be sent);

		o  Specific key exchange method messages (30 to 49).

		The provisions of Section 11 apply to unrecognized messages.

		Note, however, that during a key re-exchange, after sending a
		SSH_MSG_KEXINIT message, each party MUST be prepared to process an
		arbitrary number of messages that may be in-flight before receiving a
		SSH_MSG_KEXINIT message from the other party.
	"""
	code = 20
	def __init__(self, cookie, first_kex_packet_follows, **algs):
		self.cookie = cookie
		self.kex_algorithms = algs["kex_algorithms"]
		self.server_host_key_algorithms = algs["server_host_key_algorithms"]

		# Encryption algorithms
		self.enc_alg_c_to_s = algs["encryption_algorithms_client_to_server"]
		self.enc_alg_s_to_c = algs["encryption_algorithms_server_to_client"]

		# Mac algorithms
		self.mac_alg_c_to_s = algs["mac_algorithms_client_to_server"]
		self.mac_alg_s_to_c = algs["mac_algorithms_server_to_client"]

		# Compression algorithms
		self.com_alg_c_to_s = algs["compression_algorithms_client_to_server"]
		self.com_alg_s_to_c = algs["compression_algorithms_server_to_client"]

		# Languages
		self.languages_c_to_s = algs["languages_client_to_server"]
		self.languages_s_to_c = algs["languages_server_to_client"]

		# Extra
		self.first_kex_packet_follows = first_kex_packet_follows

	@classmethod
	def create_from_reader(cls, reader):
		# Ensure reader is at 0
		reader.head = 0
		cmd = reader.read_uint8()
		if cmd != cls.code:
			raise Exception("Using wrong msg")

		cookie = reader.read_bytes(16)
		kex_algorithms = reader.read_namelist()
		server_host_key_algorithms = reader.read_namelist()
		enc_alg_c_to_s = reader.read_namelist()
		enc_alg_s_to_c = reader.read_namelist()
		mac_alg_c_to_s = reader.read_namelist()
		mac_alg_s_to_c = reader.read_namelist()
		com_alg_c_to_s = reader.read_namelist()
		com_alg_s_to_c = reader.read_namelist()
		languages_c_to_s = reader.read_namelist()
		languages_s_to_c = reader.read_namelist()
		first_kex_packet_follows = reader.read_bool()
		_ = reader.read_uint32()

		# Check we've read everything
		if reader.remaining != 0:
			remaining_b = reader.data[-reader.remaining:]
			raise Exception(f"Still had data to read in {reader}: {remaining_b}")

		return cls(
			cookie=cookie,
			kex_algorithms=kex_algorithms,
			server_host_key_algorithms=server_host_key_algorithms,
			encryption_algorithms_client_to_server=enc_alg_c_to_s,
			encryption_algorithms_server_to_client=enc_alg_s_to_c,
			mac_algorithms_client_to_server=mac_alg_c_to_s,
			mac_algorithms_server_to_client=mac_alg_s_to_c,
			compression_algorithms_client_to_server=com_alg_c_to_s,
			compression_algorithms_server_to_client=com_alg_s_to_c,
			languages_client_to_server=languages_c_to_s,
			languages_server_to_client=languages_s_to_c,
			first_kex_packet_follows=first_kex_packet_follows)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_bytes(self.cookie)
		writer.write_namelist(self.kex_algorithms)
		writer.write_namelist(self.server_host_key_algorithms)
		writer.write_namelist(self.enc_alg_c_to_s)
		writer.write_namelist(self.enc_alg_s_to_c)
		writer.write_namelist(self.mac_alg_c_to_s)
		writer.write_namelist(self.mac_alg_s_to_c)
		writer.write_namelist(self.com_alg_c_to_s)
		writer.write_namelist(self.com_alg_s_to_c)
		writer.write_namelist(self.languages_c_to_s)
		writer.write_namelist(self.languages_s_to_c)
		writer.write_bool(self.first_kex_packet_follows)
		writer.write_uint32(0)
		return writer.data

class SSH_MSG_NEWKEYS(SSH_MSG):
	"""
	RFC4253, 7.3. Taking Keys Into Use
		Key exchange ends by each side sending an SSH_MSG_NEWKEYS message.
		This message is sent with the old keys and algorithms.  All messages
		sent after this emssage MUST use the new keys and algorithms.

		When this message is received, the new keys and algorithms MUST be
		used for receiving.

		The purpose of this message is to ensure that a party is able to
		respond with an SSH_MSG_DISCONNECT message that the other party can
		understand if something goes wrong with the key exchange.
		
			byte	SSH_MSG_NEWKEYS
	"""
	code = 21
	def __init__(self):
		pass

	@classmethod
	def create_from_reader(cls, reader):
		# Ensure reader is at 0
		reader.head = 0
		cmd = reader.read_uint8()
		if cmd != cls.code:
			raise Exception("Using wrong msg")

		# Check we've read everything
		if reader.remaining != 0:
			remaining_b = reader.data[-reader.remaining:]
			raise Exception(f"Still had data to read in {reader}: {remaining_b}")

		return cls()

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		return writer.data

	
# Specific key exchange method messages (30 to 49)
class SSH_MSG_KEXDH_INIT(SSH_MSG):
	"""
	TODO: Docstring
	"""
	code = 30
	def __init__(self, e):
		self.e = e

	@classmethod
	def create_from_reader(cls, reader):
		# Ensure reader is at 0
		reader.head = 0
		cmd = reader.read_uint8()
		if cmd != cls.code:
			raise Exception("Using wrong msg")

		e = reader.read_mpint()

		# Check we've read everything
		if reader.remaining != 0:
			remaining_b = reader.data[-reader.remaining:]
			raise Exception(f"Still had data to read in {reader}: {remaining_b}")

		return cls(
			e=e)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_mpint(self.e)
		return writer.data

class SSH_MSG_KEXDH_REPLY(SSH_MSG):
	"""
	TODO: Docstring
	"""
	code = 31
	def __init__(self, K_S, f, H_sig):
		self.K_S = K_S
		self.f = f
		self.H_sig = H_sig

	@classmethod
	def create_from_reader(cls, reader):
		# Ensure reader is at 0
		reader.head = 0
		cmd = reader.read_uint8()
		if cmd != cls.code:
			raise Exception("Using wrong msg")

		K_S = reader.read_string()
		f = reader.read_mpint()
		H_sig = reader.read_string()

		# Check we've read everything
		if reader.remaining != 0:
			remaining_b = reader.data[-reader.remaining:]
			raise Exception(f"Still had data to read in {reader}: {remaining_b}")

		return cls(
			K_S=K_S,
			f=f,
			H_sig=H_sig)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_string(self.K_S)
		writer.write_mpint(self.f)
		writer.write_string(self.H_sig)
		return writer.data


# 6. Authentication Protocol Message Numbers (50 to 79)
class SSH_MSG_USERAUTH_REQUEST(SSH_MSG):
	"""
	RFC4252, 5. Authentication Requests

		All authentication requests MUST use the following message format.
		Only the first few fields are defined; the remaining fields depend on
		the authentication method.

			byte	SSH_MSG_USERAUTH_REQUEST
			string	user name in ISO-10646 UTF-8 encoding [RFC3629]
			string	service name in US-ASCII
			string	method name in US-ASCII
			....	method specific fields

		The 'user name' and 'service name' are repeated in every new
		authentication attempt, and MAY change.  The server implementation
		MUST carefully check them in every message, and MUST flush any
		accumulated authentication states if they change.  If it is unable to
		flush an authentication state, it MUST disconnect if the 'user name'
		or 'service name' changes.

		The 'service name' specifies the service to start after
		authentication.  There may be several different authenticated
		services provided.  If the requested service is not available, the
		server MAY disconnect immediately or at any later time.  Sending a
		proper disconnect message is RECOMMENDED.  In any case, if the
		service does not exist, authentication MUST NOT be accepted.

		If the requested 'user name' does not exist, the server MAY
		disconnect, or MAY send a bogus list of acceptable authentication
		'method name' values, but never accept any.  This makes it possible
		for the server to avoid disclosing information on which accounts
		exist.  In any case, if the 'user name' does not exist, the
		authentication request MUST NOT be accepted.

		While there is usually little point for clients to send requests that
		the server does not list as acceptable, sending such requests is not
		an error, and the server SHOULD simply reject requests that it does
		not recognize.

		An authentication request MAY result in a further exchange of
		messages.  All such messages depend on the authentication 'method
		name' used, and the client MAY at any time continue with a new
		SSH_MSG_USERAUTH_REQUEST message, in which case the server MUST
		abandon the previous authentication attempt and continue with the new
		one.

		The following 'method name' values are defined.
		
			"publickey"		REQUIRED
			"password"		OPTIONAL
			"hostbased"		OPTIONAL
			"none"			NOT RECOMMENDED

		Additional 'method name' values may be defined as specified in
		[SSH-ARCH] and [SSH-NUMBERS].

	RFC4252, 7. Public Key Authentication Method: "publickey"
		The only REQUIRED authentication 'method name' is "publickey"
		authentication.  All implementations MUST support this method;
		however, not all users need to have public keys, and most local
		policies are not likely to require public key authentication for all
		users in the near future.

		With this method, the possession of a private key serves as
		authentication.  This method works by sending a signature created
		with a private key of the user.  The server MUST check that the key
		is a valid authenticator for the user, and MUST check that the
		signature is valid.  If both hold, the authentication request MUST be
		accepted; otherwise, it MUST be rejected.  Note that the server MAY
		require additional authentications after successful authentication.

		Private keys are often stored in an encrypted form at the client
		host, and the user must supply a passphrase before the signature can
		be generated.  Even if they are not, the signing operation involves
		some expensive computation.  To avoid unnecessary processing and user
		interaction, the following message is provided for querying whether
		authentication using the "publickey" method would be acceptable.

			byte	SSH_MSG_USERAUTH_REQUEST
			string	user name in ISO-10646 UTF-8 encoding [RFC3629]
			string	service name in US-ASCII
			string	"publickey"
			boolean	FALSE
			string	public key algorithm name
			string	public key blob

		Public key algorithms are defined in the transport layer
		specification [SSH-TRANS].  The 'public key blob' may contain
		certificates.

		Any public key algorithm may be offered for use in authentication.
		In particular, the list is not constrained by what was negotiated
		during key exchange.  If the server does not support some algorithm,
		it MUST simply reject the request.

		The server MUST respond to this message with either
		SSH_MSG_USERAUTH_FAILURE or with the following:

			byte	SSH_MSG_USERAUTH_PK_OK
			string	public key algorithm name from the request
			string	public key blob from the request

		To perform actual authentication, the client MAY then send a
		signature generated using the private key.  The client MAY send the
		signature directly without first verifying whether the key is
		acceptable.  The signature is sent using the following packet:

			byte	SSH_MSG_USERAUTH_REQUEST
			string	user name
			string	service name
			string	"public key"
			boolean	TRUE
			string	public key algorithm name
			string	public key to be used for authentication
			string	signature

		The value of 'signature' is a signature by the corresponding private
		key over the following data, in the following order:

			string	session identifier
			byte	SSH_MSG_USERAUTH_REQUEST
			string	user name
			string	service name
			string	"publickey"
			boolean	TRUE
			string	public key algorithm name
			string	public key to be used for authentication

		When the server receives this message, it MUST check whether the
		supplied key is acceptable for authentication, and if so, it MUST
		check whether the signature is correct.

		If both checks succeed, this method is successful.  Note that the
		server may require additional authentications.  The server MUST
		respond with SSH_MSG_USERAUTH_SUCCESS (if no more authentications are
		needed), or SSH_MSG_USERAUTH_FAILURE (if the request failed, or more
		authentications are needed).

		The following method-specific message numbers are used by the
		"publickey" authentication method.

			SSH_MSG_USERAUTH_PK_OK		60

	RFC4252, 8. Password Authentication Method: "password"
		Password authentication uses the following packets.  Note that a
		server MAY request that a user change the password.  All
		implementations SHOULD support password authentication.

			byte	SSH_MSG_USERAUTH_REQUEST
			string	user name
			string	service name
			string	"password"
			boolean	FALSE
			string	plaintext password in ISO-10646 UTF-8 encoding [RFC3629]

		Note that the 'plaintext password' value is encoded in ISO-10646
		UTF-8.  It is up to the server how to interpret the password and
		validate it against the password database.  However, if the client
		reads the password in some other encoding (e.g., ISO 8859-1 - ISO
		Latin1), it MUST convert the password to ISO-10646 UTF-8 before
		transmitting, and the server MUST convert the password to the
		encoding used on that system for passwords.

		From an internationalization standpoint, it is desired that if a user
		enters their password, the authentication process will work
		regardless of what OS and client software the user is using.  Doing
		so requires normalization.  Systems supporting non-ASCII passwords
		SHOULD always normalize passwords and user names whenever they are
		added to the database, or compared (with or without hashing) to
		existing entries in the database.  SSH implementations that both
		store the passwords and compare them SHOULD use [TFC4013] for
		normalization.

		Note that even though the cleartext password is transmitted in the
		packet, the entire packet is encrypted by the transport layer.  Both
		the server and the client should check whether the underlying
		transport layer provides confidentiality (i.e., if encryption is
		being used).  If no confidentiality is provided ("none" cipher),
		password authentication SHOULD be disabled.  If there is no
		confidentiality or no MAC, password change SHOULD be disabled

		Normally, the server responds to this message with success or
		failure.  However, if the password has expired, the server SHOULD
		indicate this by responding with SSH_MSG_USERAUTH_PASSWD_CHANGERQ.
		In any case, the server MUST NOT allow an expired password to be used
		for authentication.

			byte	SSH_MSG_USERAUTH_PASSWD_CHANGERQ
			string	prompt in ISO-10646 UTF-8 encoding [RFC3629]
			string	language tag [RFC3066]

		In this case, the client MAY continue with a different authentication
		method, or request a new password from the user and retry password
		authentication using the following message.  The client MAY also send
		this message instead of the normal password authentication request
		without the server asking for it.

			byte	SSH_MSG_USERAUTH_REQUEST
			string	user name
			string	service name
			string	"password"
			boolean	TRUE
			string	plaintext old password in ISO-10646 UTF-8 encoding
			string	plaintext new password in ISO-10646 UTF-8 encoding

		The server must reply to each request message with
		SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, or another
		SSH_MSG_USERAUTH_PASSWD_CHANGEREQ.  The meaning of these is
		as follows:

			SSH_MSG_USERAUTH_SUCCESS - The password has been changed, and
			authentication has been successfully completed.

			SSH_MSG_USERAUTH_FAILURE with partial success - The password has
			been changed, but more authentications are needed.

			SSH_MSG_USERAUTH_FAILURE without partial success - The password
			has not been changed.  Either password changing was not supported,
			or the old password was bad.  Note that if the server has already
			sent SSH_MSG_USERAUTH_PASSWD_CHANGEREQ, we know that it supports
			changing the password.

			SSH_MSG_USERAUTH_CHANGEREQ - The password was not changed because
			the new password was not acceptable (e.g., too easy to guess).

		The following method-specific message numbers are used by the
		password authentication method.

			SSH_MSG_USERAUTH_PASSWD_CHANGEREQ	60

	RFC4252, 9. Host-Based Authentication: "hostbased"
		Some sites wish to allow authentication absed on the host that the
		user is coming from and the user name on the remote host.  While this
		form of authentication is not suitable for high-security sites, it
		can be very convenient in many environments.  This form of
		authentication is OPTIONAL.  When used, special care SHOULD be taken
		to prevent a regular user from obtaining the private host key.

		The client requests this form of authentication by sending the
		following message.  It is similar to the UNIX "rhosts" and
		"hosts.equiv" styles of authentication, except that the identity of
		the client host is checked more rigorously.

		This method works by having the client send a signature created with
		the private key of the client host, which the server checks with that
		host's public key.  Once the client host's identity is established,
		authorization (but no further authentication) is performed based on
		the user names on the server and the client, and the client host
		name.

			byte	SSH_MSG_USERAUTH_REQUEST
			string	user name
			string	service name
			string	"hostbased"
			string	public key algorithm for host key
			string	public host key and certificates for client host
			string	client host name expressed as the FQDN in US-ASCII
			string	user name on the client host in ISO-10646 UTF-8 encoding
			string	signature

		Public key algorithm names for use in 'public key algorithm for host
		key' are defined in the transport layer specification [SSH-TRANS].
		The 'public host key and certificates for client host' may include
		certificates.

		The value of 'signature' is a signature with the private key of
		the following data, in this order:

			string	session identifier
			byte	SSH_MSG_USERAUTH_REQUEST
			string	user name
			string	service name
			string	"hostbased"
			string	public key algorithm for host key
			string	public host key and certificates for client host
			string	client host name expressed as the FQDN in US-ASCII
			string	user name on the client host in ISO-10646 UTF-8 encoding

		The server MUST verify that the host key actually belongs to the
		client host named in the message, that the given user on that host is
		allowed to log in, and that the 'signature' value is a valid
		signature on the appropriate value by the given host key.  The server
		MAY ignore the client 'user name', if it wants to authenticate only
		the client host.

		Whenever possible, it is RECOMMENDED that the server perform
		additional checks to verify that the network address obtained from
		the (untrusted) network matches the given client host name.  This
		makes exploiting compromised host keys more difficult.  Note that
		this may require special handling for connections coming through a
		firewall.
	"""
	code = 50
	def __init__(self):
		...

class SSH_MSG_USERAUTH_FAILURE(SSH_MSG):
	"""
	RFC4252, 5.1, Responses to Authentication Requests

		If the server rejects the authentication request, it MUST respond
		with the following:

			byte		SSH_MSG_USERAUTH_FAILURE
			name-list	authentications that can continue
			boolean		partial success

		The 'authentications that can continue' is a comma-separated name-
		list of authentication 'method name' values that may productively
		continue the authentication dialog.

		It is RECOMMENDED that servers only include those 'method name'
		values in the name-list that are actually useful.  However, it is not
		illegal to include 'method name' values that cannot be used to
		authenticate the user.

		Already successfully completed authentications SHOULD NOT be included
		in the name-list, unless they shoudl be performed again for some
		reason.

		The value of 'partial success' MUST be TRUE if the authentication
		request to which this is a response was successful.  It MUST be FALSE
		if the request was not successfully processed.

	Continued in SSH_MSG_USERAUTH_SUCCESS
	"""
	code = 51
	def __init__(self):
		...

class SSH_MSG_USERAUTH_SUCCESS(SSH_MSG):
	"""
	Continuing from SSH_MSG_USERAUTH_FAILURE

		When the server accepts authentication, it MUST respond with the
		following:

			byte	SSH_MSG_USERAUTH_SUCCESS

		Note that this is not sent after each step in a multi-method
		authentication sequence, but only when the authentication is
		complete.

		The client MAY send several authentication requests without waiting
		for responses from previous requests.  The server MUST process each
		request completely and acknowledge any failed requests with a
		SSH_MSG_USERAUTH_FAILURE message before processing the next request.

		A request that requires further messages to be exchanged will be
		aborted by a subsequent request.  A client MUST NOT send a subsequent
		request if it has not received a response from the server for a
		previous request.  A SSH_MSG_USERAUTH_FAILURE message MUST NOT be
		sent for an aborted method.

		SSH_MSG_USERAUTH_SUCCESS MUST be sent only once.  When
		SSH_MSG_USERAUTH_SUCCESS has been sent, any further authentication
		requests received after that SHOULD be silently ignored.

		Any non-authentication messages sent by the client after the request
		that resulted in SSH_MSG_USERAUTH_SUCCESS being sent MUST be passed
		to the service being run on top of this protocol.  Such messages can
		be identified by their message numbers (see Section 6).

	RFC4252, 5.2. The "none" Authentication Request
		A client may request a list of authentication 'method name' values
		that may continue by using the "none" authentication 'method name'.

		If no authentication is needed for the user, the server MUST return
		SSH_MSG_USERAUTH_SUCCESS.  Otherwise, the server MUST return
		SSH_MSG_USERAUTH_FAILURE and MAY return with it a list of methods
		that may continue in its 'authentications that can continue' value.

		This 'method name' MUST NOT be listed as supported by the server.

	RFC4252, 5.3. Completion of User Authentication
		Authentication is complete when the server has responded with
		SSH_MSG_USERAUTH_SUCCESS.  All authentication related messages
		received after sending this message SHOULD be silently ignored.

		After sending SSH_MSG_USERAUTH_SUCCESS, the server starts the
		requested service.
	"""
	code = 52
	def __init__(self):
		...

class SSH_MSG_USERAUTH_BANNER(SSH_MSG):
	"""
		RFC4252, 5.3, Banner Message

		In some jurisdictions, sending a warning message before
		authentication may be relevant for getting legal protection.  Many
		UNIX machines, for example, normally display text from /etc/issue,
		use TCP wrappers, or similar software to display a banner before
		issuing a login prompt.

		The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
		time after this authentication protocol starts and before
		authentication is successful.  This message contains text to be
		displayed to the client user before authentication is attempted.  The
		format is as follows:

			byte	SSH_MSG_USERAUTH_BANNER
			string	message in ISO-10646 UTF-8 encoding [RFC3629]
			string	language tag [RFC3066]

		By default, the client SHOULD display the 'message' on the screen.
		However, since the 'message' is likely to be sent for every login
		attempt, and since some client software will need to open a separate
		window for this warning, the client software may allow the user to
		explicitly disable the display of banners from the server.  The
		'message' may consist of multiple lines, with line breaks indicated
		by CRLF pairs.

		If the 'message' string is displayed, control character filtering,
		discussed in [SSH-ARCH], SHOULD be used to avoid attacks by sending
		terminal control characters.
	"""
	code = 53
	def __init__(self):
		...

class SSH_MSG_USERAUTH_MISC_RESP(SSH_MSG):
	"""
	Handles SSH_MSG_USERAUTH_PK_OK
	Handles SSH_MSG_USERAUTH_PASSWORD_CHANGEREQ
	"""
	code = 60

	def __init__(self):
		...

	# def __init_subclass__(self):
	# 	...

class SSH_MSG_USERAUTH_PK_OK(SSH_MSG_USERAUTH_MISC_RESP):
	"""
	RFC4252, 7. Public Key Authentication Method: "publickey"
		The server MUST respond to this message with either
		SSH_MSG_USERAUTH_FAILURE or with the following:

			byte	SSH_MSG_USERAUTH_PK_OK
			string	public key algorithm name from the request
			string	public key blob from the request
	"""
	code = 60
	def __init__(self):
		...

class SSH_MSG_USERAUTH_PASSWD_CHANGEREQ(SSH_MSG_USERAUTH_MISC_RESP):
	"""
	RFC4252, 8. Password Authentication Method: "password"
		Normally, the server responds to this message with success or
		failure.  However, if the password has expired, the server SHOULD
		indicate this by responding with SSH_MSG_USERAUTH_PASSWD_CHANGERQ.
		In any case, the server MUST NOT allow an expired password to be used
		for authentication.

			byte	SSH_MSG_USERAUTH_PASSWD_CHANGERQ
			string	prompt in ISO-10646 UTF-8 encoding [RFC3629]
			string	language tag [RFC3066]

		In this case, the client MAY continue with a different authentication
		method, or request a new password from the user and retry password
		authentication using the following message.  The client MAY also send
		this message instead of the normal password authentication request
		without the server asking for it.
	"""
	def __init__(self):
		...


# ???
class SSH_MSG_GLOBAL_REQUEST(SSH_MSG):
	"""
	"""
	code = 80
	def __init__(self):
		...

class SSH_MSG_REQUEST_SUCCESS(SSH_MSG):
	"""
	"""
	code = 81
	def __init__(self):
		...

class SSH_MSG_REQUEST_FAILURE(SSH_MSG):
	"""
	"""
	code = 82
	def __init__(self):
		...


# ???
class SSH_MSG_CHANNEL_OPEN(SSH_MSG):
	"""
	"""
	code = 90
	def __init__(self):
		...

class SSH_MSG_CHANNEL_OPEN_CONFIRMATION(SSH_MSG):
	"""
	"""
	code = 91
	def __init__(self):
		...

class SSH_MSG_CHANNEL_OPEN_FAILURE(SSH_MSG):
	"""
	"""
	code = 92
	def __init__(self):
		...

class SSH_MSG_CHANNEL_WINDOW_ADJUST(SSH_MSG):
	"""
	"""
	code = 93
	def __init__(self):
		...

class SSH_MSG_CHANNEL_DATA(SSH_MSG):
	"""
	"""
	code = 94
	def __init__(self, recipient_channel, data):
		self.recipient_channel = recipient_channel
		self.data = data

	@classmethod
	def create_from_reader(cls, reader):
		# Ensure reader is at 0
		reader.head = 0
		cmd = reader.read_uint8()
		if cmd != cls.code:
			raise Exception("Using wrong msg")

		recipient_channel = reader.read_uint32()
		data = reader.read_string()

		# Check we've read everything
		if reader.remaining != 0:
			remaining_b = reader.data[-reader.remaining:]
			raise Exception(f"Still had data to read in {reader}: {remaining_b}")

		return cls(
			recipient_channel=recipient_channel,
			data=data)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_uint32(self.recipient_channel)
		writer.write_string(self.data)
		return writer.data


class SSH_MSG_CHANNEL_EXTENDED_DATA(SSH_MSG):
	"""
	"""
	code = 95
	def __init__(self):
		...

class SSH_MSG_CHANNEL_EOF(SSH_MSG):
	"""
	"""
	code = 96
	def __init__(self):
		...

class SSH_MSG_CHANNEL_CLOSE(SSH_MSG):
	"""
	"""
	code = 97
	def __init__(self):
		...

class SSH_MSG_CHANNEL_REQUEST(SSH_MSG):
	"""
	"""
	code = 98
	def __init__(self):
		...

class SSH_MSG_CHANNEL_SUCCESS(SSH_MSG):
	"""
	"""
	code = 99
	def __init__(self):
		...

class SSH_MSG_CHANNEL_FAILURE(SSH_MSG):
	"""
	"""
	code = 100
	def __init__(self):
		...
