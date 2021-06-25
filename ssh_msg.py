
from helpers import ReadHelper, WriteHelper



# TODO: Add method that just creates a msg rather than get_class
class SSH_MSG:
	msg = {}

	def __init__(self):
		...

	def __init_subclass__(cls):
		"""Used to add subclasses to the msg dict to look them up"""
		if cls.code in SSH_MSG.msg:
			SSH_MSG.msg[cls.code].append(cls)
		else:
			SSH_MSG.msg[cls.code] = [cls]

	@classmethod
	def create_from_packet(cls, packet):
		reader = ReadHelper(packet)

		# Read the code and try find the correct handler
		cmd_code = reader.read_uint8()

		# Try each message class. Some messages share a code.
		msg_classes = cls.get_classes(cmd_code)
		for msg_class in msg_classes:
			try:
				# Get the data using the respective class
				data = msg_class.create_from_reader(reader)
				if data is None:
					raise Exception(f"No data returned from reader for {msg_class}")

				# Check that the reader is finished
				if reader.remaining != 0:
					remaining_b = reader.data[-reader.remaining:]
					raise Exception(f"Still had data to read in {reader}: {remaining_b}")

			except Exception as e:
				# Just failed to read packet with that class. try next.
				print(e)
				pass

			finally:
				# If we succeeded, we have a packet we can use
				break

		return data

	@classmethod
	def get_classes(cls, code):
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
		reason_code = reader.read_uint32()
		description = reader.read_string(ascii=True)
		language_tag = reader.read_string()

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
		service_name = reader.read_string(ascii=True)

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
	def __init__(self, service_name):
		self.service_name = service_name

	@classmethod
	def create_from_reader(cls, reader):
		service_name = reader.read_string(ascii=True)

		return cls(
			service_name=service_name)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_string(self.service_name)
		return writer.data


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
		e = reader.read_mpint()

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
		K_S = reader.read_string()
		f = reader.read_mpint()
		H_sig = reader.read_string()

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
	def __init__(self, user_name, service_name, method_name, **kwargs):
		self.user_name = user_name
		self.service_name = service_name
		self.method_name = method_name

		# Handle kwargs
		for kwarg_name in kwargs:
			self.__setattr__(kwarg_name, kwargs[kwarg_name])
		
		# self._ = kwargs.get("_")
		# self.public_key_algorithm_name = kwargs.get("public_key_algorithm_name")
		# self.public_key_blob = kwargs.get("public_key_blob")
		# self.public_key = kwargs.get("public_key")
		# self.signature = kwargs.get("signature")
		# self.changing_password = kwargs.get("changing_password")
		# self.password = kwargs.get("password")
		# self.new_password = kwargs.get("new_password")
		# TODO: Include fields for hostbased and none

	@classmethod
	def create_from_reader(cls, reader):
		user_name = reader.read_string(ascii=True)
		service_name = reader.read_string(ascii=True)
		method_name = reader.read_string(ascii=True)

		if method_name == "publickey":
			print("TODO: Check the handling of publickey")
			_ = reader.read_bool()

			if not _:
				public_key_algorithm_name = reader.read_string(ascii=True)
				public_key_blob = reader.read_string()
				return cls(
					user_name=user_name,
					service_name=service_name,
					method_name=method_name,
					_=_,
					public_key_algorithm_name=public_key_algorithm_name,
					public_key_blob=public_key_blob)

			else:
				public_key_algorithm_name = reader.read_string(ascii=True)
				public_key = reader.read_string()
				signature = reader.read_string()
				return cls(
					user_name=user_name,
					service_name=service_name,
					method_name=method_name,
					_=_,
					public_key_algorithm_name=public_key_algorithm_name,
					public_key=public_key,
					signature=signature)

		elif method_name == "password":
			changing_password = reader.read_bool()

			if not changing_password:
				password = reader.read_string(ascii=True)
				return cls(
					user_name=user_name,
					service_name=service_name,
					method_name=method_name,
					changing_password=changing_password,
					password=password)

			else:
				password = reader.read_string(ascii=True)
				new_password = reader.read_string(ascii=True)
				return cls(
					user_name=user_name,
					service_name=service_name,
					method_name=method_name,
					changing_password=changing_password,
					password=password,
					new_password=new_password)

		elif method_name == "hostbased":
			print("TODO: Check the handling of hostbased")
			public_key_algorithm_name = reader.read_string(ascii=True)
			...

		elif method_name == "none":
			return cls(
				user_name=user_name,
				service_name=service_name,
				method_name=method_name)

		else:
			raise Exception("Unhandled method_name for USERAUTH_REQUEST")

	# TODO: to_bytes method

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
	def __init__(self, auths, partial_success):
		self.auths = auths
		self.partial_success = partial_success

	@classmethod
	def create_from_reader(cls, reader):
		auths = reader.read_namelist()
		partial_success = reader.read_bool()
		return cls(
			auths=auths,
			partial_success=partial_success)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_namelist(self.auths)
		writer.write_bool(self.partial_success)
		return writer.data

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
		pass

	@classmethod
	def create_from_reader(cls, reader):
		return cls()

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		return writer.data

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
	code = 60
	def __init__(self, prompt, language_tag=""):
		self.prompt = prompt
		self.language_tag = language_tag

	@classmethod
	def create_from_reader(cls, reader):
		prompt = reader.read_string(ascii=True)
		language_tag = reader.read_string(ascii=True)

		return cls(
			prompt=prompt,
			language_tag=language_tag)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_string(self.prompt)
		writer.write_string(self.language_tag)
		return writer.data


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
	RFC4254, 5.1. Opening a Channel
		When either side wishes to open a new channel, it allocates a local
		number for the channel.  It then sends the following message to the
		other side, and includes the local channel number and initial window
		size in the message.

			byte	SSH_MSG_CHANNEL_OPEN
			string	channel type in US-ASCII only
			uint32	sender channel
			uint32	initial window size
			uint32	maximum packet size
			....	channel type specific data follows

		The 'channel type' is a name, as described in [SSH-ARCH] and
		[SSH-NUMBERS], with similar extension mechanisms.  The 'sender
		channel' is a local identifier for the channel used by the sender of
		this message.  The 'initial window size' specifies how many bytes of
		channel data can be sent to the sender of this message without
		adjusting the window.  The 'maximum packet size' specifies the
		maximum size of an individual data packet that can be sent to the
		sender.  For example, one might want to use smaller packets for
		interactive connections to get better interactive response on slow
		links.

		The remote side then decides whether it can open the channel, and
		responds with either SSH_MSG_CHANNEL_OPEN_CONFIRMATION or
		SSH_MSG_CHANNEL_OPEN_FAILURE.

	Continued in SSH_MSG_CHANNEL_OPEN_CONFIRMATION
	"""
	code = 90
	def __init__(self,
		channel_type, sender_channel,
		initial_window_size, maximum_packet_size,
		**kwargs
	):
		self.channel_type = channel_type
		self.sender_channel = sender_channel
		self.initial_window_size = initial_window_size
		self.maximum_packet_size = maximum_packet_size

		# Handle kwargs
		for kwarg_name in kwargs:
			self.__setattr__(kwarg_name, kwargs[kwarg_name])

		# self.originator_address = kwargs.get("originator_address")
		# self.originator_port = kwargs.get("originator_port")
		# self.address_that_was_connected = kwargs.get("address_that_was_connected")
		# self.port_that_was_connected = kwargs.get("port_that_was_connected")
		# self.host_to_connect = kwargs.get("host_to_connect")
		# self.port_to_connect = kwargs.get("port_to_connect")

	# TODO: Write the reader and to_bytes
	@classmethod
	def create_from_reader(cls, reader):
		channel_type = reader.read_string(ascii=True)
		sender_channel = reader.read_uint32()
		initial_window_size = reader.read_uint32()
		maximum_packet_size = reader.read_uint32()

		if channel_type == "session":
			return cls(
				channel_type=channel_type,
				sender_channel=sender_channel,
				initial_window_size=initial_window_size,
				maximum_packet_size=maximum_packet_size)

		elif channel_type == "x11":
			originator_address = reader.read_string(ascii=True)
			originator_port = reader.read_uint32()
			return cls(
				channel_type=channel_type,
				sender_channel=sender_channel,
				initial_window_size=initial_window_size,
				maximum_packet_size=maximum_packet_size,
				originator_address=originator_address,
				originator_port=originator_port)

		elif channel_type == "forwarded-tcpip":
			address_that_was_connected = reader.read_string(ascii=True)
			port_that_was_connected = reader.read_uint32()
			originator_address = reader.read_string(ascii=True)
			originator_port = reader.read_uint32()
			return cls(
				channel_type=channel_type,
				sender_channel=sender_channel,
				initial_window_size=initial_window_size,
				maximum_packet_size=maximum_packet_size,
				address_that_was_connected=address_that_was_connected,
				port_that_was_connected=port_that_was_connected,
				originator_address=originator_address,
				originator_port=originator_port)

		elif channel_type == "direct-tcpip":
			host_to_connect = reader.read_string(ascii=True)
			port_to_connect = reader.read_uint32()
			originator_address = reader.read_string(ascii=True)
			originator_port = reader.read_uint32()
			return cls(
				channel_type=channel_type,
				sender_channel=sender_channel,
				initial_window_size=initial_window_size,
				maximum_packet_size=maximum_packet_size,
				host_to_connect=host_to_connect,
				port_to_connect=port_to_connect,
				originator_address=originator_address,
				originator_port=originator_port)

		else:
			raise Exception("Unhandled channel_type for CHANNEL_OPEN")

	# TODO: Write to_bytes method

class SSH_MSG_CHANNEL_OPEN_CONFIRMATION(SSH_MSG):
	"""
	Continued from SSH_MSG_CHANNEL_OPEN
		.
			byte	SSH_MSG_CHANNEL_OPEN_CONFIRMATION
			uint32	recipient channel
			uint32	sender channel
			uint32	initial window size
			uint32	maximum packet size
			....	channel type specific data follows

		The 'recipient channel' is the channel number given in the original
		open request, and 'sender channel' is the channel number allocated by
		the other side.

	Continued in SSH_MSG_CHANNEL_OPEN_FAILURE
	"""
	code = 91
	def __init__(self,
		recipient_channel, sender_channel,
		initial_window_size, maximum_packet_size,
		**kwargs
	):
		self.recipient_channel = recipient_channel
		self.sender_channel = sender_channel
		self.initial_window_size = initial_window_size
		self.maximum_packet_size = maximum_packet_size

		# Handle kwargs
		for kwarg_name in kwargs:
			self.__setattr__(kwarg_name, kwargs[kwarg_name])

	# TODO: Write the reader and to_bytes

	# @classmethod
	# def create_from_reader(cls, reader):
	# 	recipient_channel = reader.read_


	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_uint32(self.recipient_channel)
		writer.write_uint32(self.sender_channel)
		writer.write_uint32(self.initial_window_size)
		writer.write_uint32(self.maximum_packet_size)
		# TODO: Handle channel type specific data
		return writer.data

class SSH_MSG_CHANNEL_OPEN_FAILURE(SSH_MSG):
	"""
	Continued from SSH_MSG_CHANNEL_OPEN_CONFIRMATION
		.
			byte	SSH_MSG_CHANNEL_OPEN_FAILURE
			uint32	recipient channel
			uint32	reason code
			string	description in ISO-10646 UTF-8 encoding [RFC3629]
			string	language tag [RFC3066]

		If the recipient of the SSH_MSG_CHANNEL_OPEN message does not support
		the specified 'channel type', it simply responds with
		SSH_MSG_CHANNEL_OPEN_FAILURE.  The client MAY show the 'description'
		string to the user.  if this is done, the client software should take
		the precautions discussed in [SSH-ARCH].

		The SSH_MSG_CHANNEL_OPEN_FAILURE 'reason code' values are defined in
		the following table.  Note that the values for the 'reason code' are
		given in decimal format for readability, but they are actually uint32
		values.

			Symbolic name							reason code
			-------------							-----------
			SSH_OPEN_ADMINISTRATIVELY_PROHIBITED	1
			SSH_OPEN_CONNECT_FAILED					2
			SSH_OPEN_UNKNOWN_CHANNEL_TYPE			3
			SSH_OPEN_RESOURCE_SHORTAGE				4

		Requests for assignments of new SSH_MSG_CHANNEL_OPEN 'reason code'
		values (and associated 'description' text) in the range of 0x00000005
		to 0xFDFFFFFF MUST be done through the IETF CONSENSUS method, as
		described in [RFC2434].  The IANA will not assign Channel Connection
		Failure 'reason code' values in the range of 0xFE000000 to
		0xFFFFFFFF.  Channel Connection Failure 'reason code' values in that
		range are left for PRIVATE USE, as described in [RFC2434].
	"""
	code = 92

	ADMINISTRATIVELY_PROHIBITED	= lambda rc,d: SSH_MSG_CHANNEL_OPEN_FAILURE(rc,1,d)
	CONNECT_FAILED				= lambda rc,d: SSH_MSG_CHANNEL_OPEN_FAILURE(rc,2,d)
	UNKNOWN_CHANNEL_TYPE		= lambda rc,d: SSH_MSG_CHANNEL_OPEN_FAILURE(rc,3,d)
	RESOURCE_SHORTAGE			= lambda rc,d: SSH_MSG_CHANNEL_OPEN_FAILURE(rc,4,d)

	def __init__(self,
		recipient_channel, reason_code,
		description, language_tag=""
	):
		self.recipient_channel = recipient_channel
		self.reason_code = reason_code
		self.description = description
		self.language_tag = language_tag

	@classmethod
	def create_from_reader(cls, reader):
		recipient_channel = reader.read_uint32()
		reason_code = reader.read_uint32()
		description = reader.read_string()
		language_tag = reader.read_string()

		return cls(
			recipient_channel=recipient_channel,
			reason_code=reason_code,
			description=description,
			language_tag=language_tag)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_uint32(self.recipient_channel)
		writer.write_uint32(self.reason_code)
		writer.write_string(self.description)
		writer.write_string(self.language_tag)
		return writer.data

class SSH_MSG_CHANNEL_WINDOW_ADJUST(SSH_MSG):
	"""
	RFC4254, 5.2. Data Transfer
		The window size specifies how many bytes the other party can send
		before it must wait for the window to be adjusted.  Both parties use
		the following message to adjust the window.

			byte	SSH_MSG_CHANNEL_WINDOW_ADJUST
			uint32	recipient channel
			uint32	bytes to add

		After receiving this message, the recipient MAY send the given number
		of bytes more than it was previously allowed to send; the window size
		is incremented.  Implementations MUST correctly handle window sizes
		of up to 2^32 - 1 bytes.  THe window MUST NOT be increased above
		2^32 - 1 bytes.
	"""
	code = 93
	def __init__(self):
		...

class SSH_MSG_CHANNEL_DATA(SSH_MSG):
	"""
	RFC4254, 5.2. Data Transfer
		Data transfer is done with messages of the following type.

			byte	SSH_MSG_CHANNEL_DATA
			uint32	recipient channel
			string	data

		The maximum amount of data allowed is determined by the maximum
		packet size for the channel, and the current window size, whichever
		is smaller.  The window size is decremented by the amount of data
		sent.  Both parties MAY ignore all extra data sent after the allowed
		window is empty.

		Implementations are expected to have some limit on the SSH transport
		layer packet size (any limit for received packets MUST be 32768 bytes
		or larger, as described in [SSH-TRANS]).  The implementation of the
		SSH connection layer

		o  MUST NOT advertise a maximum packet size that would result in
		   transport packets larger than its transport layer is willing to
		   receive.

		o  MUST NOT generate data packets larger than its transport layer is
		   willing to send, even if the remote end would be willing to accept
		   very large packets.

		Additionally, some channels can transfer several types of data.  An
		example of this is strderr data from interactive sessions.  Such data
		can be passed with SSH_MSG_CHANNEL_EXTENDED_DATA messages, where a
		separate integer specifies the type of data.  The available types and
		their interpretation depend on the type of channel.
	"""
	code = 94
	def __init__(self, recipient_channel, data):
		self.recipient_channel = recipient_channel
		self.data = data

	@classmethod
	def create_from_reader(cls, reader):
		recipient_channel = reader.read_uint32()
		data = reader.read_string()
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
	From RFC4254, 5.2. Data Transfer
		.
			byte	SSH_MSG_CHANNEL_EXTENDED_DATA
			uint32	recipient channel
			uint32	data_type_code
			string	data

		Data sent with these messages consumes the same window as ordinary
		data.

		Currently, only the following type is defined.  Note that the value
		for the 'data_type_code' is given in decimal format for readability,
		but the values are actually uint32 values.

			Symbolic name				data_type_code
			-------------				--------------
			SSH_EXTENDED_DATA_STDERR	1

		Extended Channel Data Transfer 'data_type_code' values MUST be
		assigned sequentially.  Requests for assignments of new Extended
		Channel Data Transfer 'data_type_code' values and their associated
		Extended Channel Data Transfer 'data' strings, in the range of
		0x00000002 to 0xFDFFFFFF, MUST be done through the IETF CONSENSUS
		method as described in [RFC2434].  The IANA will not assign Extended
		0xFE000000 to 0xFFFFFFFF.  Extended Channel Data Transfer
		'data_type_code' values in that range are left for PRIVATE USE, as
		described in [RFC2434].  As is noted, the actual instructions to the
		IANA are in [SSH-NUMBERS].
	"""
	code = 95
	def __init__(self, recipient_channel, data_type_code, data):
		self.recipient_channel = recipient_channel
		self.data_type_code = data_type_code
		self.data = data

	@classmethod
	def create_from_reader(cls, reader):
		recipient_channel = reader.read_uint32()
		data_type_code = reader.read_uint32()
		data = reader.read_string()
		return cls(
			recipient_channel=recipient_channel,
			data_type_code=data_type_code,
			data=data)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_uint32(self.recipient_channel)
		writer.write_uint32(self.data_type_code)
		writer.write_string(self.data)
		return writer.data

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
	RFC4254, 5.4. Channel-Specific Requests
		Many 'channel type' values have extensions that are specific to that
		particular 'channel type'.  An example is requesting a pty (pseudo
		terminal) for an interactive session.

		All channel-specific requests use the following format.

			byte	SSH_MSG_CHANNEL_REQUEST
			uint32	recipient channel
			string	request type in US-ASCII characters only
			boolean	want reply
			....	type-specific data follows

		If 'want reply' is FALSE, no response will be sent to the request.
		Otherwise, the recipient responds with either
		SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_FAILURE, or request-specific
		continuation messages.  If the request is not recognized or is not
		supported for the channel, SSH_MSG_CHANNEL_FAILURE is returned.

		This message does not consime window space and can be sent even if no
		window space is available.  The values of 'request type' are local to
		each channel type.

		The client is allowed to send further messages without waiting for
		the response to the request.

		'request type' names follow the DNS extensibility naming convention
		outlined in [SSH-ARCH] and [SSH-NUMBERS].

	RFC4254, 6.2. Requesting a Pseudo-Terminal
		A pseudo-terminal can be allocated for the session by sending the
		following message.

			byte	SSH_MSG_CHANNEL_REQUEST
			uint32	recipient channel
			string	"pty-req"
			boolean	want_reply
			string	TERM environment variable value (e.g., vt100)
			uint32	terminal width, characters (e.g., 80)
			uint32	terminal height, rows (e.g., 24)
			uint32	terminal width, pixels (e.g., 640)
			uint32	terminal height, pixels (e.g., 480)
			string	encoded terminal modes

		The 'encoded terminal modes' are described in Section 8.  Zero
		dimension parameters MUST be ignored.  The character/row dimensions
		override the pixel dimensions (when nonzero).  Pixel dimensions refer
		to the drawable area of the window.

		The dimension parameters are only informational.

		The cliekt SHOULD ignore pty requests.

	RFC4254, 6.3.1. Requesting X11 Forwarding
		... I'll skip this for now

	RFC4254, 6.4. Environment Variable Passing.
		Environment variables may be passed to the shell/command to be
		started later.  Uncontrolled setting of environment variables in a
		privileged process can be a security hazard.  It is recommended that
		implementations either maintain a list of allowable variable names or
		only set environment variables after the server process has dropped
		sufficient privileges.

			byte	SSH_MSG_CHANNEL_REQUEST
			uint32	recipient channel
			string	"env"
			boolean	want reply
			string	variable name
			string	variable value

	RFC4254, 6.5. Starting a Shell or a Command
		Once the session has been set up, a program is started at the remote
		end.  The program can be a shell, an application program, or a
		subsystem with a host-independent name.  Only one of these requests
		can succeed per channel.

			byte	SSH_MSG_CHANNEL_REQUEST
			uint32	recipient channel
			string	"shell"
			boolean	want reply

		This message will request that the user's default shell (typically
		defined in /etc/passwd in UNIX systems) be started at the other end.

			byte	SSH_MSG_CHANNEL_REQUEST
			uint32	recipient channel
			string	"exec"
			boolean	want reply
			string	command

		This message will request that the server start the execution of the
		given command.  The 'command' string may contain a path.  Normal
		precautions MUST be taken to prevent the execution of unauthorized
		commands.

			byte	SSH_MSG_CHANNEL_REQUEST
			uint32	recipient channel
			string	"subsystem"
			boolean	want reply
			string	subsystem name

		This last form executes a predefined subsystem.  It is expected that
		these will include a general file transfer mechanism, and possibly
		other features.  Implementations may also allow configuring more such
		mechanisms.  As the user's shell is usually used to execute the
		subsystem, it si advisable for the subsystem protocol to have a
		"magic cookie" at the beginning of the protocol transaction to
		distinguish it from arbitrary output generated by shell
		initialization scripts, etc.  This spurious output from the shell may
		be filtered out either at the server or at the client.

		The server SHOULD NOT halt the execution of the protcol stack when
		starting a shell or a program.  All input and output from these
		SHOULD be redirected to the channel or to the encrypted tunnel.

		It is RECOMMENDED that the reply to these messages be requested and
		checked.  The client SHOULD ignore these messages.

		Subsystem names follow the DNS extensibility naming convention
		outlined in [SSH-NUMBERS].
	"""
	code = 98
	def __init__(self,
		recipient_channel, request_type,
		want_reply, **kwargs
	):
		self.recipient_channel = recipient_channel
		self.request_type = request_type
		self.want_reply = want_reply

		# Handle kwargs
		for kwarg_name in kwargs:
			self.__setattr__(kwarg_name, kwargs[kwarg_name])

	@classmethod
	def create_from_reader(cls, reader):
		recipient_channel = reader.read_uint32()
		request_type = reader.read_string(ascii=True)
		want_reply = reader.read_bool()
		
		if request_type == "pty-req":
			term_environment_variable = reader.read_string()
			terminal_width = reader.read_uint32()
			terminal_height = reader.read_uint32()
			terminal_width_pixels = reader.read_uint32()
			terminal_height_pixels = reader.read_uint32()
			encoded_terminal_modes = reader.read_string()
			return cls(
				recipient_channel=recipient_channel,
				request_type=request_type,
				want_reply=want_reply,
				term_environment_variable=term_environment_variable,
				terminal_width=terminal_width,
				terminal_height=terminal_height,
				terminal_width_pixels=terminal_width_pixels,
				terminal_height_pixels=terminal_height_pixels,
				encoded_terminal_modes=encoded_terminal_modes)

		elif request_type == "x11-req":
			single_connection = reader.read_bool()
			x11_authentication_protocol = reader.read_string(ascii=True)
			x11_authentication_cookie = reader.read_string()
			x11_screen_number = reader.read_uint32()
			return cls(
				recipient_channel=recipient_channel,
				request_type=request_type,
				want_reply=want_reply,
				single_connection=single_connection,
				x11_authentication_protocol=x11_authentication_protocol,
				x11_authentication_cookie=x11_authentication_cookie,
				x11_screen_number=x11_screen_number)

		elif request_type == "env":
			variable_name = reader.read_string()
			variable_value = reader.read_string()
			return cls(
				recipient_channel=recipient_channel,
				request_type=request_type,
				want_reply=want_reply,
				variable_name=variable_name,
				variable_value=variable_value)

		elif request_type == "shell":
			return cls(
				recipient_channel=recipient_channel,
				request_type=request_type,
				want_reply=want_reply)

		elif request_type == "exec":
			command = reader.read_string()
			return cls(
				recipient_channel=recipient_channel,
				request_type=request_type,
				want_reply=want_reply,
				command=command)

		elif request_type == "subsystem":
			subsystem_name = reader.read_string()
			return cls(
				recipient_channel=recipient_channel,
				request_type=request_type,
				want_reply=want_reply,
				subsystem_name=subsystem_name)

		else:
			raise Exception("Unhandled request_type for CHANNEL_REQUEST")


	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_string(self.request_type)
		writer.write_bool(self.want_reply)
		# TODO: Handle type specific data
		return writer.data

class SSH_MSG_CHANNEL_SUCCESS(SSH_MSG):
	"""
	"""
	code = 99
	def __init__(self, recipient_channel):
		self.recipient_channel = recipient_channel

	@classmethod
	def create_from_reader(cls, reader):
		recipient_channel = reader.read_uint32()
		return cls(
			recipient_channel=recipient_channel)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_uint32(self.recipient_channel)
		return writer.data

class SSH_MSG_CHANNEL_FAILURE(SSH_MSG):
	"""
	"""
	code = 100
	def __init__(self, recipient_channel):
		self.recipient_channel = recipient_channel

	@classmethod
	def create_from_reader(cls, reader):
		recipient_channel = reader.read_uint32()
		return cls(
			recipient_channel=recipient_channel)

	def to_bytes(self):
		writer = WriteHelper()
		writer.write_uint8(self.code)
		writer.write_uint32(self.recipient_channel)
		return writer.data
