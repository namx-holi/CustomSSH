import binascii
from os import urandom as os_urandom
from Crypto.Hash import SHA1

from helpers import GenericHandler
from helpers import WriteHelper

"""
"""

# TODO: handle eliptic curve?


class DiffieHellmanHandler(GenericHandler):

	def __init__(self):
		# User's public key
		self.e = None

		# Our private and public keys
		self.y = None
		self.f = None

		# Shared secret
		self.K = None

		# Exchange hash
		self.H = None

		# Used for calculations
		self.g = None
		self.p = None
		self.hash_method = None

		# Session identifier
		self.session_id = None

		# Encryption keys
		self.initial_iv_c_to_s = None
		self.initial_iv_s_to_c = None
		self.enc_key_c_to_s = None
		self.enc_key_s_to_c = None
		self.mac_key_c_to_s = None
		self.mac_key_s_to_c = None


	def set_algorithm(self, alg):
		alg = self.algorithms.get(alg, None)
		if alg is None:
			raise Exception("algorithm not handled")

		available = alg.get("available")
		if not available:
			raise Exception("algorithm not available")

		self.g = alg["g"]
		self.p = alg["p"]
		self.bits = alg["bits"]
		self.hash_method = alg["hash_method"]

		# self.group = alg["group"]
		# self.dh = pyDH.DiffieHellman(self.group)


	def HASH(self, data):
		return self.hash_method.new(data).digest()

	def set_client_public_key(self, e):
		self.e = e

	def gen_server_public_key(self):
		self.y = int(binascii.hexlify(os_urandom(32)), base=16)
		self.f = pow(self.g, self.y, self.p)
		return self.f

	def gen_shared_key(self):
		shared_secret = pow(self.e, self.y, self.p)
		self.K = shared_secret
		return self.K


	def generate_H(self, V_C, V_S, I_C, I_S, K_S):
		w = WriteHelper()
		w.write_string(V_C)
		w.write_string(V_S)
		w.write_string(I_C)
		w.write_string(I_S)
		w.write_string(K_S)
		w.write_mpint(self.e)
		w.write_mpint(self.f)
		w.write_mpint(self.K)
		self.H = self.HASH(w.data)

		# The exchange hash H from the first key exchange is
		# used as the session identifier.
		if self.session_id is None:
			self.session_id = self.H

		return self.H


	def generate_keys(self):
		# TODO: handle hash not generating long enough key

		# Initial IV client to server
		w = WriteHelper()
		w.write_mpint(self.K)
		w.write_bytes(self.H)
		w.write_bytes(b"A")
		w.write_bytes(self.session_id)
		self.initial_iv_c_to_s = self.HASH(w.data)

		# Initial IV server to client
		w = WriteHelper()
		w.write_mpint(self.K)
		w.write_bytes(self.H)
		w.write_bytes(b"B")
		w.write_bytes(self.session_id)
		self.initial_iv_s_to_c = self.HASH(w.data)

		# Encryption key client to server
		w = WriteHelper()
		w.write_mpint(self.K)
		w.write_bytes(self.H)
		w.write_bytes(b"C")
		w.write_bytes(self.session_id)
		self.enc_key_c_to_s = self.HASH(w.data)

		# Encryption key server to client
		w = WriteHelper()
		w.write_mpint(self.K)
		w.write_bytes(self.H)
		w.write_bytes(b"D")
		w.write_bytes(self.session_id)
		self.enc_key_s_to_c = self.HASH(w.data)

		# Integrity key client to server
		w = WriteHelper()
		w.write_mpint(self.K)
		w.write_bytes(self.H)
		w.write_bytes(b"E")
		w.write_bytes(self.session_id)
		self.mac_key_c_to_s = self.HASH(w.data)

		# Integrity key server to client
		w = WriteHelper()
		w.write_mpint(self.K)
		w.write_bytes(self.H)
		w.write_bytes(b"F")
		w.write_bytes(self.session_id)
		self.mac_key_s_to_c = self.HASH(w.data)



# List of algorithms and ref of their methods
# Higher prio = first
DiffieHellmanHandler.algorithms = {
	"diffie-hellman-group1-sha1": {
		"available": False,
		"priority": -1000,
		# NOTE, Method named after group 1 despite using group 2
		# "method": DiffieHellmanHandler.dh_group2_sha1,
		# "group": 2,
		"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF,
		"g": 2,
		"bits": 1024,
		"hash_method": SHA1
	},
	"diffie-hellman-group14-sha1": {
		"available": True,
		"priority": 1000,
		# "method": DiffieHellmanHandler.dh_group14_sha1,
		# "group": 14,
		"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
		"g": 2,
		"bits": 2048,
		"hash_method": SHA1
	}
}
