
"""
RFC 4250, 4.1. Message Numbers

The Message Number is a byte value that describes the payload of a
packet.
"""

from data_types import DataReader, DataWriter


class SSH_MSG:
	"""
	Parent class of all SSH messages. This is used to read in a raw
	payload and turn it into an instance of the respective message
	"""

	msg_types = {}

	def __init_subclass__(cls):
		"""
		Adds subclasses to the list of available message types. cls is
		the child class, not the parent class.
		"""
		SSH_MSG.msg_types[cls.message_number] = cls

	@classmethod
	def read_msg(cls, payload):
		"""
		Used to create an instance of the correct type of message from
		a raw payload
		"""
		r = DataReader(payload)

		# Read the code and try to find the correct message class
		message_number = r.read_uint8()

		msg_class = cls.msg_types.get(message_number, None)
		if msg_class is None:
			raise Exception(f"Unhandled message number {message_number}")

		return msg_class.from_reader(r)

	@classmethod
	def from_reader(cls, r):
		"""
		Inherited by message classes. Needs to be implemented to handle
		the remaining data in the payload after reading the message
		number.
		"""
		print(f"CLASS {cls} DOES NOT HAVE from_reader METHOD")
		return None

	def payload(self):
		"""
		Inherited by message classes. Needs to be implemented to turn
		a message instance into raw payload
		"""
		print(f"CLASS {self.__class__} DOES NOT HAVE payload METHOD")
		return None



# 1 to 19: Transport layer generic (e.g., disconnect, ignore, debug,
#  etc.)
class SSH_MSG_DISCONNECT(SSH_MSG):
	message_number = 1
	
	# All different reason codes
	# TODO: Convert these to classes that have the correct name
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

	# TODO: Handle language tag?
	def __init__(self, reason_code, description, language_tag=""):
		self.reason_code = reason_code
		self.description = description
		self.language_tag = language_tag

	@classmethod
	def from_reader(cls, r):
		reason_code = r.read_uint32()
		description = reader.read_string()
		language_tag = reader.read_string()
		return cls(reason_code, description, language_tag)

	def payload(self):
		w = DataWriter()
		w.write_uint8(self.message_number)
		w.write_uint32(self.reason_code)
		w.write_string(self.description)
		w.write_string(self.language_tag)
		return w.data

# class SSH_MSG_IGNORE(SSH_MSG):
# 	message_number = 2
# 	# TODO
# 	...

# class SSH_MSG_UNIMPLEMENTED(SSH_MSG):
# 	message_number = 3
# 	# TODO
# 	...

# class SSH_MSG_DEBUG(SSH_MSG):
# 	message_number = 4
# 	# TODO
# 	...

class SSH_MSG_SERVICE_REQUEST(SSH_MSG):
	message_number = 5

	def __init__(self, service_name):
		self.service_name = service_name

	@classmethod
	def from_reader(cls, r):
		service_name = r.read_string()
		return cls(service_name)

	def payload(self):
		w = DataWriter()
		w.write_uint8(self.message_number)
		w.write_string(self.service_name)
		return w.data

# class SSH_MSG_SERVICE_ACCEPT(SSH_MSG):
# 	message_number = 6
# 	# TODO
# 	...


# 20 to 29: Algorithm negotiation
class SSH_MSG_KEXINIT(SSH_MSG):
	message_number = 20

	def __init__(self,
		cookie,
		kex_algorithms,
		server_host_key_algorithms,
		encryption_algorithms_client_to_server,
		encryption_algorithms_server_to_client,
		mac_algorithms_client_to_server,
		mac_algorithms_server_to_client,
		compression_algorithms_client_to_server,
		compression_algorithms_server_to_client,
		languages_client_to_server,
		languages_server_to_client,
		first_kex_packet_follows
	):
		self.cookie = cookie
		self.kex_algorithms = kex_algorithms
		self.server_host_key_algorithms = server_host_key_algorithms
		self.encryption_algorithms_client_to_server = encryption_algorithms_client_to_server
		self.encryption_algorithms_server_to_client = encryption_algorithms_server_to_client
		self.mac_algorithms_client_to_server = mac_algorithms_client_to_server
		self.mac_algorithms_server_to_client = mac_algorithms_server_to_client
		self.compression_algorithms_client_to_server = compression_algorithms_client_to_server
		self.compression_algorithms_server_to_client = compression_algorithms_server_to_client
		self.languages_client_to_server = languages_client_to_server
		self.languages_server_to_client = languages_server_to_client
		self.first_kex_packet_follows = first_kex_packet_follows

	@classmethod
	def from_reader(cls, r):
		cookie = r.read_bytes(16)
		kex_algorithms = r.read_namelist()
		server_host_key_algorithms = r.read_namelist()
		encryption_algorithms_client_to_server = r.read_namelist()
		encryption_algorithms_server_to_client = r.read_namelist()
		mac_algorithms_client_to_server = r.read_namelist()
		mac_algorithms_server_to_client = r.read_namelist()
		compression_algorithms_client_to_server = r.read_namelist()
		compression_algorithms_server_to_client = r.read_namelist()
		languages_client_to_server = r.read_namelist()
		languages_server_to_client = r.read_namelist()
		first_kex_packet_follows = r.read_bool()
		_ = r.read_uint32() # Reserved for future extension

		return cls(
			cookie=cookie,
			kex_algorithms=kex_algorithms,
			server_host_key_algorithms=server_host_key_algorithms,
			encryption_algorithms_client_to_server=encryption_algorithms_client_to_server,
			encryption_algorithms_server_to_client=encryption_algorithms_server_to_client,
			mac_algorithms_client_to_server=mac_algorithms_client_to_server,
			mac_algorithms_server_to_client=mac_algorithms_server_to_client,
			compression_algorithms_client_to_server=compression_algorithms_client_to_server,
			compression_algorithms_server_to_client=compression_algorithms_server_to_client,
			languages_client_to_server=languages_client_to_server,
			languages_server_to_client=languages_server_to_client,
			first_kex_packet_follows=first_kex_packet_follows)

	def payload(self):
		w = DataWriter()
		w.write_uint8(self.message_number)
		w.write_bytes(self.cookie)
		w.write_namelist(self.kex_algorithms)
		w.write_namelist(self.server_host_key_algorithms)
		w.write_namelist(self.encryption_algorithms_client_to_server)
		w.write_namelist(self.encryption_algorithms_server_to_client)
		w.write_namelist(self.mac_algorithms_client_to_server)
		w.write_namelist(self.mac_algorithms_server_to_client)
		w.write_namelist(self.compression_algorithms_client_to_server)
		w.write_namelist(self.compression_algorithms_server_to_client)
		w.write_namelist(self.languages_client_to_server)
		w.write_namelist(self.languages_server_to_client)
		w.write_bool(self.first_kex_packet_follows)
		w.write_uint32(0) # Reserved for future extension
		return w.data

class SSH_MSG_NEWKEYS(SSH_MSG):
	message_number = 21

	def __init__(self):
		pass

	@classmethod
	def from_reader(cls, r):
		return cls()

	def payload(self):
		w = DataWriter()
		w.write_uint8(self.message_number)
		return w.data


# 30 to 49: Key exchange method specific (numbers can be reused for
#  different authentication methods)
class SSH_MSG_KEXDH_INIT(SSH_MSG):
	message_number = 30

	def __init__(self, e):
		self.e = e

	@classmethod
	def from_reader(cls, r):
		e = r.read_mpint()
		return cls(e)

	def payload(self):
		w = DataWriter()
		w.write_uint8(self.message_number)
		w.write_mpint(e)
		return w.data

class SSH_MSG_KEXDH_REPLY(SSH_MSG):
	message_number = 31

	def __init__(self, K_S, f, H_sig):
		self.K_S = K_S
		self.f = f
		self.H_sig = H_sig

	@classmethod
	def from_reader(cls, r):
		K_S = r.read_string()
		f = r.read_mpint()
		H_sig = r.read_string()
		return cls(K_S, f, H_sig)

	def payload(self):
		w = DataWriter()
		w.write_uint8(self.message_number)
		w.write_string(self.K_S)
		w.write_mpint(self.f)
		w.write_string(self.H_sig)
		return w.data


# # 50 to 59: User authentication generic
# class SSH_MSG_USERAUTH_REQUEST(SSH_MSG):
# 	message_number = 50
# class SSH_MSG_USERAUTH_FAILURE(SSH_MSG):
# 	message_number = 51
# class SSH_MSG_USERAUTH_SUCCESS(SSH_MSG):
# 	message_number = 52
# class SSH_MSG_USERAUTH_BANNER(SSH_MSG):
# 	message_number = 53


# # 60 to 79: User authentication method specific (numbers can be reused
# #  for different authentication methods)
# ...


# # 80 to 89: Connection protocol generic
# class SSH_MSG_GLOBAL_REQUEST(SSH_MSG):
# 	message_number = 80
# class SSH_MSG_REQUEST_SUCCESS(SSH_MSG):
# 	message_number = 81
# class SSH_MSG_REQUEST_FAILURE(SSH_MSG):
# 	message_number = 82


# # 90 to 127: Channel related methods
# class SSH_MSG_CHANNEL_OPEN(SSH_MSG):
# 	message_number = 90
# class SSH_MSG_CHANNEL_OPEN_CONFIRMATION(SSH_MSG):
# 	message_number = 91
# class SSH_MSG_CHANNEL_OPEN_FAILURE(SSH_MSG):
# 	message_number = 92
# class SSH_MSG_CHANNEL_WINDOW_ADJUST(SSH_MSG):
# 	message_number = 93
# class SSH_MSG_CHANNEL_DATA(SSH_MSG):
# 	message_number = 94
# class SSH_MSG_CHANNEL_EXTENDED_DATA(SSH_MSG):
# 	message_number = 95
# class SSH_MSG_CHANNEL_EOF(SSH_MSG):
# 	message_number = 96
# class SSH_MSG_CHANNEL_CLOSE(SSH_MSG):
# 	message_number = 97
# class SSH_MSG_CHANNEL_REQUEST(SSH_MSG):
# 	message_number = 98
# class SSH_MSG_CHANNEL_SUCCESS(SSH_MSG):
# 	message_number = 99
# class SSH_MSG_CHANNEL_FAILURE(SSH_MSG):
# 	message_number = 100


# # 128 to 191: Reserved
# ...


# # 192 to 255: Local extensions. Private use.
# ...



# """
# RFC 4250, 4.2. Disconnection Messages Reason Codes and Descriptions

# The Disconnection Message 'reason code' is a uint32 value. The
# associated Disconnection Message 'description' is a human-readable
# message that describes the disconnect reason.
# """
# class SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:
# 	reason_code = 1
# class SSH_DISCONNECT_PROTOCOL_ERROR:
# 	reason_code = 2
# class SSH_DISCONNECT_KEY_EXCHANGE_FAILED:
# 	reason_code = 3
# class SSH_DISCONNECT_RESERVED:
# 	reason_code = 4
# class SSH_DISCONNECT_MAC_ERROR:
# 	reason_code = 5
# class SSH_DISCONNECT_COMPRESSION_ERROR:
# 	reason_code = 6
# class SSH_DISCONNECT_SERVICE_NOT_AVAILABLE:
# 	reason_code = 7
# class SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
# 	reason_code = 8
# class SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:
# 	reason_code = 9
# class SSH_DISCONNECT_CONNECTION_LOST:
# 	reason_code = 10
# class SSH_DISCONNECT_BY_APPLICATION:
# 	reason_code = 11
# class SSH_DISCONNECT_TOO_MANY_CONNECTIONS:
# 	reason_code = 12
# class SSH_DISCONNECT_AUTH_CANCELLED_BY_USER:
# 	reason_code = 13
# class SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE:
# 	reason_code = 14
# class SSH_DISCONNECT_ILLEGAL_USER_NAME:
# 	reason_code = 15




# """
# RFC 4250, 4.3 Channel Connection Failure Reason Codes and Descriptions

# The Channel Connection Failure 'reason code' is a uint32 value. The
# associated Channel Connection Failure 'description' text is a
# human-readable message that describes the channel connection failure
# reason.
# """
# class SSH_OPEN_ADMINISTRATIVELY_PROHIBITED:
# 	reason_code = 1
# class SSH_OPEN_CONNECT_FAILED:
# 	reason_code = 2
# class SSH_OPEN_UNKNOWN_CHANNEL_TYPE:
# 	reason_code = 3
# class SSH_OPEN_RESOURCE_SHORTAGE:
# 	reason_code = 4
