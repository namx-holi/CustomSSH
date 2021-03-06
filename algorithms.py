
import binascii
import struct
from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA512
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Signature import pkcs1_15
from os import urandom
import zlib

from config import Config
from data_types import DataWriter
from messages import SSH_MSG_KEXINIT, SSH_MSG_KEX_ECDH_REPLY



class NoMatchingAlgorithm(Exception):
	...



# Helper method to find the first match between two algorithm lists.
#  Client's algorithm list is preferenced.
def _find_match(cls, client_algos, server_algos):
	algo_name = next((
		algo_name for algo_name in client_algos
		if algo_name in server_algos), None)
	if algo_name is None:
		return None
	return cls.get_algorithm(algo_name)()





class AlgorithmHandler:

	def __init__(self):
		# Our Host Key object
		self.host_key = None

		# Our session ID
		self.session_id = None

		# Algorithms being used
		self.kex_algorithm = None
		self.server_host_key_algorithm = None
		self.encryption_algo_c_to_s = None
		self.encryption_algo_s_to_c = None
		self.mac_algo_c_to_s = None
		self.mac_algo_s_to_c = None
		self.compression_algo_c_to_s = None
		self.compression_algo_s_to_c = None

		# Values we need access to
		self.V_C = None # Client's identification string
		self.V_S = None # Server's identification string
		self.I_C = None # The payload of the client's SSH_MSG_KEXINIT
		self.I_S = None # The payload of the server's SSH_MSG_KEXINIT
		self.H = None


	def set_exchange_strings(self, V_C, V_S):
		self.V_C = V_C.rstrip(b"\r\n")
		self.V_S = V_S.rstrip(b"\r\n")


	def generate_server_kexinit(self,
		languages_client_to_server=[],
		languages_server_to_client=[],
		first_kex_packet_follows=False
	):
		# Generate our own SSH_MSG_KEXINIT
		cookie = urandom(16)
		resp = SSH_MSG_KEXINIT(
			cookie=cookie,
			kex_algorithms=KexAlgorithm.algorithms(),
			server_host_key_algorithms=ServerHostKeyAlgorithm.algorithms(),
			encryption_algorithms_client_to_server=EncryptionAlgorithm.client_to_server_algorithms(),
			encryption_algorithms_server_to_client=EncryptionAlgorithm.server_to_client_algorithms(),
			mac_algorithms_client_to_server=MacAlgorithm.client_to_server_algorithms(),
			mac_algorithms_server_to_client=MacAlgorithm.server_to_client_algorithms(),
			compression_algorithms_client_to_server=CompressionAlgorithm.client_to_server_algorithms(),
			compression_algorithms_server_to_client=CompressionAlgorithm.server_to_client_algorithms(),
			languages_client_to_server=languages_client_to_server,
			languages_server_to_client=languages_server_to_client,
			first_kex_packet_follows=first_kex_packet_follows)

		# Store the server's SSH_MSG_KEXINIT payload
		self.I_S = resp.payload()

		return resp


	def handle_client_KEXINIT(self, client_kexinit):
		# Store the client's SSH_MSG_KEXINIT payload
		self.I_C = client_kexinit.payload()

		# Try find matches for each algorithm. Client preference.
		self.kex_algorithm = _find_match(
			KexAlgorithm,
			client_kexinit.kex_algorithms,
			KexAlgorithm.algorithms())
		if self.kex_algorithm is None:
			raise NoMatchingAlgorithm()

		self.server_host_key_algorithm = _find_match(
			ServerHostKeyAlgorithm,
			client_kexinit.server_host_key_algorithms,
			ServerHostKeyAlgorithm.algorithms())
		if self.server_host_key_algorithm is None:
			raise NoMatchingAlgorithm()

		self.encryption_algo_c_to_s = _find_match(
			EncryptionAlgorithm,
			client_kexinit.encryption_algorithms_client_to_server,
			EncryptionAlgorithm.client_to_server_algorithms())
		if self.encryption_algo_c_to_s is None:
			raise NoMatchingAlgorithm()

		self.encryption_algo_s_to_c = _find_match(
			EncryptionAlgorithm,
			client_kexinit.encryption_algorithms_server_to_client,
			EncryptionAlgorithm.server_to_client_algorithms())
		if self.encryption_algo_s_to_c is None:
			raise NoMatchingAlgorithm()

		self.mac_algo_c_to_s = _find_match(
			MacAlgorithm,
			client_kexinit.mac_algorithms_client_to_server,
			MacAlgorithm.client_to_server_algorithms())
		if self.mac_algo_c_to_s is None:
			raise NoMatchingAlgorithm()

		self.mac_algo_s_to_c = _find_match(
			MacAlgorithm,
			client_kexinit.mac_algorithms_server_to_client,
			MacAlgorithm.server_to_client_algorithms())
		if self.mac_algo_s_to_c is None:
			raise NoMatchingAlgorithm()

		self.compression_algo_c_to_s = _find_match(
			CompressionAlgorithm,
			client_kexinit.compression_algorithms_client_to_server,
			CompressionAlgorithm.client_to_server_algorithms())
		if self.compression_algo_c_to_s is None:
			raise NoMatchingAlgorithm()

		self.compression_algo_s_to_c = _find_match(
			CompressionAlgorithm,
			client_kexinit.compression_algorithms_server_to_client,
			CompressionAlgorithm.server_to_client_algorithms())
		if self.compression_algo_s_to_c is None:
			raise NoMatchingAlgorithm()


	def handle_client_KEX_ECDH_INIT(self, client_kex_ecdh_init):
		# TODO: Handle ServerHostKeyAlgorithm properly

		# TODO: Verify received Q_C is valid.
		...

		# Initialise the key exchange algorithm to generate our own
		#  keys and calculate a shared key
		self.kex_algorithm.initialise(client_kex_ecdh_init.Q_C)

		# Initialise our host key and save the blob
		self.server_host_key_algorithm.initialise()

		# Generate our exchange hash H
		w = DataWriter() # SSH-TRANS 8.
		w.write_string(self.V_C)
		w.write_string(self.V_S)
		w.write_string(self.I_C)
		w.write_string(self.I_S)
		w.write_string(self.server_host_key_algorithm.K_S)
		w.write_mpint(self.kex_algorithm.Q_C) # TODO: Handle as octet string
		w.write_mpint(self.kex_algorithm.Q_S) # TODO: Handle as octet string
		w.write_mpint(self.kex_algorithm.K)
		self.H = self.kex_algorithm.HASH(w.data) # exchange hash

		# The exchange hash H from the first key exchange is used as the
		#  session identifier
		if self.session_id is None:
			self.session_id = self.H

		# Calculate the signature of H
		H_sig = self.server_host_key_algorithm.sign(self.H)

		# Create a key exchange reply
		server_kex_ecdh_reply = SSH_MSG_KEX_ECDH_REPLY(
			K_S=self.server_host_key_algorithm.K_S,
			Q_S=self.kex_algorithm.Q_S,
			H_sig=H_sig
		)
		return server_kex_ecdh_reply


	def setup_algorithms(self):
		# K is stored as an int but it needs to be handled as an mpint
		#  for the purpose of generating the keys
		w = DataWriter()
		w.write_mpint(self.kex_algorithm.K)
		K = w.data

		# Alias the HASH method from key exchange method to make code
		#  a bit shorter
		HASH = self.kex_algorithm.HASH

		# Method to reduce duplicate code to handle generating a key
		#  with the correct length
		def _generate_key(X, length): # SSH-TRANS 7.2.
			# HASH(K || H || session_id)
			key = HASH(K + self.H + X + self.session_id)
			# If the key length needed is longer than the output of
			#  HASH, the key is extended by computing HASH of the concat
			#  of K and H and the entire key so far, and appending the
			#  resulting bytes to the key. This process is repeated
			#  until enough key material is available.
			while len(key) < length:
				key += HASH(K + self.H + key)

			# Key data MUST be taken from the beginning of the hash output.
			return key[:length]

		# Set up each algorithm
		self.encryption_algo_c_to_s.initialise(
			_generate_key(b"A", self.encryption_algo_c_to_s.iv_length),
			_generate_key(b"C", self.encryption_algo_c_to_s.key_length))
		self.encryption_algo_s_to_c.initialise(
			_generate_key(b"B", self.encryption_algo_s_to_c.iv_length),
			_generate_key(b"D", self.encryption_algo_s_to_c.key_length))
		self.mac_algo_c_to_s.initialise(
			_generate_key(b"E", self.mac_algo_c_to_s.hash_length))
		self.mac_algo_s_to_c.initialise(
			_generate_key(b"F", self.mac_algo_s_to_c.hash_length))

		self.compression_algo_c_to_s.initialise()
		self.compression_algo_s_to_c.initialise()


	def enable_algorithms(self, message_handler):
		message_handler.encryption_algo_c_to_s = self.encryption_algo_c_to_s
		message_handler.encryption_algo_s_to_c = self.encryption_algo_s_to_c
		message_handler.mac_algo_c_to_s = self.mac_algo_c_to_s
		message_handler.mac_algo_s_to_c = self.mac_algo_s_to_c
		message_handler.compression_algo_c_to_s = self.compression_algo_c_to_s
		message_handler.compression_algo_s_to_c = self.compression_algo_s_to_c



###################
# Algorithm Types #
###################
class BothWayAlgorithm:
	"""
	Same algorithm used for client->server and server->client
	"""
	_algorithms = OrderedDict()
	enabled = False
	
	@classmethod
	def algorithms(cls):
		return [
			a for a in cls._algorithms.keys()
			if cls._algorithms[a].enabled]

	@classmethod
	def get_algorithm(cls, algo_name):
		return cls._algorithms[algo_name]

class OneWayAlgorithm(BothWayAlgorithm):
	"""
	Possible to have a different algorithm for client->server than
	server->client
	"""
	_algorithms = OrderedDict()
	_client_to_server = OrderedDict()
	_server_to_client = OrderedDict()
	client_enabled = False
	server_enabled = False

	@classmethod
	def client_to_server_algorithms(cls):
		return [
			a for a in cls._client_to_server.keys()
			if cls._client_to_server[a].client_enabled]

	@classmethod
	def server_to_client_algorithms(cls):
		return [
			a for a in cls._server_to_client.keys()
			if cls._server_to_client[a].server_enabled]


######################
# Generic Algorithms #
######################
class KexAlgorithm(BothWayAlgorithm):
	_algorithms = OrderedDict()
	def __init_subclass__(cls):
		KexAlgorithm._algorithms[cls.__qualname__] = cls

class ServerHostKeyAlgorithm(BothWayAlgorithm):
	_algorithms = OrderedDict()
	def __init_subclass__(cls):
		ServerHostKeyAlgorithm._algorithms[cls.__qualname__] = cls

class EncryptionAlgorithm(OneWayAlgorithm):
	_algorithms = OrderedDict()
	_client_to_server = OrderedDict()
	_server_to_client = OrderedDict()
	def __init_subclass__(cls):
		EncryptionAlgorithm._algorithms[cls.__qualname__] = cls
		if "decrypt" in dir(cls):
			EncryptionAlgorithm._client_to_server[cls.__qualname__] = cls
		if "encrypt" in dir(cls):
			EncryptionAlgorithm._server_to_client[cls.__qualname__] = cls

class MacAlgorithm(OneWayAlgorithm):
	_algorithms = OrderedDict()
	_client_to_server = OrderedDict()
	_server_to_client = OrderedDict()
	def __init_subclass__(cls):
		MacAlgorithm._algorithms[cls.__qualname__] = cls
		if "verify" in dir(cls):
			MacAlgorithm._client_to_server[cls.__qualname__] = cls
		if "generate" in dir(cls):
			MacAlgorithm._server_to_client[cls.__qualname__] = cls

class CompressionAlgorithm(OneWayAlgorithm):
	_algorithms = OrderedDict()
	_client_to_server = OrderedDict()
	_server_to_client = OrderedDict()
	def __init_subclass__(cls):
		CompressionAlgorithm._algorithms[cls.__qualname__] = cls
		if "decompress" in dir(cls):
			CompressionAlgorithm._client_to_server[cls.__qualname__] = cls
		if "compress" in dir(cls):
			CompressionAlgorithm._server_to_client[cls.__qualname__] = cls



##################
# Kex Algorithms #
##################
class DH_Group14_SHA1(KexAlgorithm):
	__qualname__ = "diffie-hellman-group14-sha1"
	enabled = True

	generator = 2
	prime = int.from_bytes(bytes.fromhex("""
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
		29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
		EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
		E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
		C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
		83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
		670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
		E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
		DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
		15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
	"""), "big")
	order = 2048

	def initialise(self, Q_C):
		# TODO: Handle Q_C as an octet string
		# self.Q_C = int.from_bytes(Q_C, "big", signed=True)
		self.Q_C = Q_C

		# Generate our random number y (0 < y < q = 2^order)
		self.y = random.randrange(1, 2**self.order)

		# Calculate our public key and the shared secret
		self.Q_S = pow(self.generator, self.y, self.prime) # g^y % p
		self.K = pow(self.Q_C, self.y, self.prime) # e^y % p

	def HASH(self, data):
		return SHA1.new(data).digest()

class DH_Group16_SHA512(KexAlgorithm):
	__qualname__ = "diffie-hellman-group16-sha512"
	enabled = True

	generator = 2
	prime = int.from_bytes(bytes.fromhex("""
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
		29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
		EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
		E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
		C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
		83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
		670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
		E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
		DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
		15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
		ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
		ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
		F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
		BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
		43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
		88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
		2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
		287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
		1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
		93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
		FFFFFFFF FFFFFFFF
	"""), "big")
	order = 4096

	def initialise(self, Q_C):
		# TODO: Handle Q_C as an octet string
		self.Q_C = Q_C

		# Generate our random number y (0 < y < q = 2^order)
		self.y = random.randrange(1, 2**self.order)

		# Calculate our public key and the shared secret
		self.Q_S = pow(self.generator, self.y, self.prime) # g^y % p
		self.K = pow(self.Q_C, self.y, self.prime) # e^y % p

	def HASH(self, data):
		return SHA512.new(data).digest()



##############################
# Server Host Key Algorithms #
##############################
class SSH_RSA(ServerHostKeyAlgorithm):
	__qualname__ = "ssh-rsa"
	enabled = True

	def initialise(self):
		filename = Config.HOST_KEYS["ssh-rsa"]
		with open(filename, "r") as f:
			self.key = RSA.import_key(f.read())

		# Generate the key blob
		w = DataWriter() # SSH-TRANS 6.6.
		w.write_string("ssh-rsa")
		w.write_mpint(self.key.e)
		w.write_mpint(self.key.n)
		self.K_S = w.data

	def sign(self, data):
		sig = pkcs1_15.new(self.key).sign(SHA1.new(data))

		# TODO: What is meant by the following?
		# The value for 'rsa_signature_blob' is encoded as a string
		#  containing s (which is an integer, without lengths or
		#  padding, unsigned, and in network byte order).
		w = DataWriter() # SSH-TRANS 6.6.
		w.write_string("ssh-rsa")
		w.write_string(sig)
		return w.data



#########################
# Encryption Algorithms #
#########################
class AES128_CBC(EncryptionAlgorithm):
	__qualname__ = "aes128-cbc"
	client_enabled = True
	server_enabled = True

	iv_length = 16
	key_length = 16

	def initialise(self, iv, key):
		self.cipher = AES.new(key, AES.MODE_CBC, iv)

	def encrypt(self, data):
		return self.cipher.encrypt(data)

	def decrypt(self, data):
		return self.cipher.decrypt(data)


class AES128_CTR(EncryptionAlgorithm):
	__qualname__ = "aes128-ctr"
	client_enabled = True
	server_enabled = True

	iv_length = 16
	key_length = 16

	def initialise(self, iv, key):
		initial_value = int.from_bytes(iv, "big", signed=False) # RFC4344, 4.
		self.cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=initial_value)

	def encrypt(self, data):
		return self.cipher.encrypt(data)

	def decrypt(self, data):
		return self.cipher.decrypt(data)


class AES192_CTR(EncryptionAlgorithm):
	__qualname__ = "aes192-ctr"
	client_enabled = True
	server_enabled = True

	iv_length = 16
	key_length = 24

	def initialise(self, iv, key):
		initial_value = int.from_bytes(iv, "big", signed=False) # RFC4344, 4.
		self.cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=initial_value)

	def encrypt(self, data):
		return self.cipher.encrypt(data)

	def decrypt(self, data):
		return self.cipher.decrypt(data)


class AES256_CTR(EncryptionAlgorithm):
	__qualname__ = "aes256-ctr"
	client_enabled = True
	server_enabled = True

	iv_length = 16
	key_length = 32

	def initialise(self, iv, key):
		initial_value = int.from_bytes(iv, "big", signed=False) # RFC4344, 4.
		self.cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=initial_value)

	def encrypt(self, data):
		return self.cipher.encrypt(data)

	def decrypt(self, data):
		return self.cipher.decrypt(data)



##################
# MAC Algorithms #
##################
class HMAC_SHA1(MacAlgorithm):
	__qualname__ = "hmac-sha1"
	client_enabled = True
	server_enabled = True

	key_length = 20
	hash_length = 20

	def initialise(self, key):
		self.key = key

	def generate(self, data, sequence_number):
		sequence_number_b = struct.pack(">I", sequence_number)
		h = HMAC.new(self.key, digestmod=SHA1)
		h.update(sequence_number_b + data)
		return h.digest()

	def verify(self, data, sequence_number, mac):
		return self.generate(data, sequence_number) == mac



##########################
# Compression Algorithms #
##########################
class NoCompression(CompressionAlgorithm):
	__qualname__ = "none"
	client_enabled = True
	server_enabled = True

	def initialise(self):
		...

	def compress(self, data):
		return data

	def decompress(self, data):
		return data


class LZ77(CompressionAlgorithm):
	__qualname__ = "zlib"
	client_enabled = True
	server_enabled = True

	def initialise(self):
		self.compressobj = zlib.compressobj(level=6)
		self.decompressobj = zlib.decompressobj()

	def compress(self, data):
		return (
			self.compressobj.compress(data)
			+ self.compressobj.flush(zlib.Z_PARTIAL_FLUSH))

	def decompress(self, data):
		return self.decompressobj.decompress(data)
