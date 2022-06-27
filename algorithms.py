
import binascii
import struct
from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from Crypto.PublicKey import RSA
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
		algo_name for algo_name in set(client_algos)
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
		self.K_S = None # The host key. Blob of self.key
		self.H = None
		self.HASH = None # Method used to TODO: WRITE THIS


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

		# Retrieve our host key, and also save as a blob
		# ssh-rsa
		with open(Config.RSA_KEY) as f:
			self.host_key = RSA.import_key(f.read())
		w = DataWriter() # SSH-TRANS 6.6.
		w.write_string("ssh-rsa")
		w.write_mpint(self.host_key.e)
		w.write_mpint(self.host_key.n)
		self.K_S = w.data

		# Generate our exchange hash H
		self.HASH = lambda x: SHA1.new(x) # diffie-hellman-group14-sha1
		w = DataWriter() # SSH-TRANS 8.
		w.write_string(self.V_C)
		w.write_string(self.V_S)
		w.write_string(self.I_C)
		w.write_string(self.I_S)
		w.write_string(self.K_S)
		# TODO: Handle Q_C and Q_S as an octet string
		w.write_mpint(self.kex_algorithm.Q_C)
		w.write_mpint(self.kex_algorithm.Q_S)
		w.write_mpint(self.kex_algorithm.K)
		# diffie-hellman-group14-sha1
		self.H = self.HASH(w.data).digest() # exchange hash

		# The exchange hash H from the first key exchange is used as the
		#  session identifier
		if self.session_id is None:
			self.session_id = self.H

		# Calculate the signature of H
		# SSH_RSA (pkcs1_15), diffie-hellman-group14-sha1
		sig = pkcs1_15.new(self.host_key).sign(SHA1.new(self.H))
		w = DataWriter() # SSH-TRANS 6.6.
		w.write_string("ssh-rsa")
		w.write_uint32(len(sig))
		w.write_byte(sig)
		H_sig = w.data

		# Create a key exchange reply
		server_kex_ecdh_reply = SSH_MSG_KEX_ECDH_REPLY(
			K_S=self.K_S,
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

		# Method to reduce duplicate code to handle generating a key
		#  with the correct length
		def _generate_key(X, length): # SSH-TRANS 7.2.
			# HASH(K || H || session_id)
			key = self.HASH(K + self.H + X + self.session_id).digest()
			# If the key length needed is longer than the output of
			#  HASH, the key is extended by computing HASH of the concat
			#  of K and H and the entire key so far, and appending the
			#  resulting bytes to the key. This process is repeated
			#  until enough key material is available.
			while len(key) < length:
				key += HASH(K + self.H + key).digest()

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
	prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

	def initialise(self, Q_C):
		# TODO: Handle Q_C as an octet string
		# self.Q_C = int.from_bytes(Q_C, "big", signed=True)
		self.Q_C = Q_C

		# Generate our own key pair, and calculate the shared secret
		self.y = int(binascii.hexlify(urandom(32)), base=16)
		self.Q_S = pow(self.generator, self.y, self.prime) # g^y % p
		self.K = pow(self.Q_C, self.y, self.prime) # e^y % p



##############################
# Server Host Key Algorithms #
##############################
class SSH_RSA(ServerHostKeyAlgorithm):
	__qualname__ = "ssh-rsa"
	enabled = True



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


# TODO: Fix an incorrect header check on decompress, and sometimes
#  compression just doesn't work
class LZ77(CompressionAlgorithm):
	__qualname__ = "zlib"
	client_enabled = False
	server_enabled = False

	def initialise(self):
		self.compressobj = zlib.compressobj(level=6)
		self.decompressobj = zlib.decompressobj()

	def compress(self, data):
		return (
			self.compressobj.compress(data)
			+ self.compressobj.flush(zlib.Z_PARTIAL_FLUSH))

	def decompress(self, data):
		return self.decompressobj.decompress(data)
