from Crypto.Cipher import AES

from helpers import GenericHandler

"""
	6.3.	Encryption
	An encryption algorithm and key will be negotiated during the key
	exchange.  When encryption is in effect, the packet length, padding
	length, payload, and padding fields of each packet MUST be encrypted
	with the given algorithm.

	The encrypted data in all packets sent in one direction SHOULD be
	considered a single data stream.  For example, initialization vectors
	SHOULD be passed from the end of one packet to the beginning of the
	next packet.  All ciphers SHOULD use keys with an effective key
	length of 128 bits or more.

	The ciphers in each direction MUST run independently of each other.
	Implementations MUST allow the algorithm for each direction to be
	independently selected, if multiple algorithms are allowed by local
	policy.  In practice however, it is RECOMMENDED that teh same
	algorithm be used in both directions.

	The following ciphers are currently defined:
		3des-cbc		REQUIRED	 three-key 3DES in CBC mode
		blowfish-cbc	OPTIONAL	 Blowfish in CBC mode
		twofish256-cbc	OPTIONAL	 Twofish in CBC mode, with a 256-bit key
		twofish-cbc		OPTIONAL	 alias for "twofish256-cbc"
		twofish192-cbc	OPTIONAL	 Twofish with a 192-bit key
		twofish128-cbc	OPTIONAL	 Twofish with a 128-bit key
		aes256-cbc		OPTIONAL	 AES in CBC mode, with a 256-bit key
		aes192-cbc		OPTIONAL	 AES with a 192-bit key
		aes128-cbc		RECOMMENDED	 AES with a 128-bit key
		serpent256-cbc	OPTIONAL	 Serpent in CBC mode, with a 256-bit key
		serpent192-cbc	OPTIONAL	 Serpent with a 192-bit key
		serpent128-cbc	OPTIONAL	 Serpent with a 128-bit key
		arcfour			OPTIONAL	 The ARCFOUR stream cipher with a 128-bit key
		idea-cbc		OPTIONAL	 IDEA in CBC mode
		cast128-cbc		OPTIONAL	 CAST-128 in CBC mode
		none			OPTIONAL	 no encryption; NOT RECOMMENDED

	The "3des-cbc" cipher is a three-key triple-DES (encrypt-decrypt-
	encrypt), where the first 8 bytes of the key are used for the first
	encryption, the next 8 bytes for the decryption, and the following 8
	bytes for the final encryption.  This requries 24 bytes of key data
	(of which 168 bits are actually used).  To implement CBC mode, outer
	chaining MUST be used (i.e., there is only one initialization
	vector).  This is a block cipher with 8-byte blocks.  This algorithm
	is defined in [FIPS-46-3].  Note that since this algorithm only has
	an effective key length of 112 bits ([SCHNEIER]), it does not meet
	the specifications that SSH encryption algorithms should use keys of
	128 bits or more.  However, this algorithm is still REQUIRED for
	historical reasons.
"""


class EncryptionHandler(GenericHandler):

	def __init__(self, packet_handler):
		self.handler = packet_handler
		self.set_encryption_algorithm("none")
		self.set_decryption_algorithm("none")


	def prepare_encryption_algorithm(self, alg):
		self.prepared_encryption_algorithm = alg
	def set_prepared_encryption_algorithm(self):
		self.set_encryption_algorithm(self.prepared_encryption_algorithm)
		self.prepared_encryption_algorithm = None
	
	def prepare_decryption_algorithm(self, alg):
		self.prepared_decryption_algorithm = alg
	def set_prepared_decryption_algorithm(self):
		self.set_decryption_algorithm(self.prepared_decryption_algorithm)
		self.prepared_decryption_algorithm = None


	def set_encryption_algorithm(self, alg):
		alg = self.algorithms.get(alg, None)
		if alg is None:
			raise Exception(f"algorithm {alg} not handled")
		
		available = alg.get("available")
		if not available:
			raise Exception(f"algorithm {alg} not available")

		self.encryption_method = alg.get("encryption_method")
		self.encryption_block_size = alg.get("block_size")
		self.encryption_key_size = alg.get("key_size")

		# Reset the cipher object
		self.encryption_cipher = None
	
	def set_decryption_algorithm(self, alg):
		alg = self.algorithms.get(alg, None)
		if alg is None:
			raise Exception(f"algorithm {alg} not handled")
		
		available = alg.get("available")
		if not available:
			raise Exception(f"algorithm {alg} not available")

		self.decryption_method = alg.get("decryption_method")
		self.decryption_block_size = alg.get("block_size")
		self.decryption_key_size = alg.get("key_size")

		# Reset the cipher object
		self.decryption_cipher = None


	def set_encryption_key(self, key):
		if len(key)*8 < self.encryption_key_size:
			raise Exception(f"Encryption key size needs to be {self.encryption_key_size} bits")
		self.encryption_key = key[0:self.encryption_key_size//8]

	def set_decryption_key(self, key):
		if len(key)*8 < self.decryption_key_size:
			raise Exception(f"Decryption key size needs to be {self.decryption_key_size} bits")
		self.decryption_key = key[0:self.decryption_key_size//8]


	def set_encryption_iv(self, iv):
		if len(iv)*8 < self.encryption_key_size:
			raise Exception(f"Encryption IV size needs to be {self.encryption_key_size} bits")
		self.encryption_iv = iv[0:self.encryption_key_size//8]

	def set_decryption_iv(self, iv):
		if len(iv)*8 < self.decryption_key_size:
			raise Exception(f"Decryption IV size needs to be {self.decryption_key_size} bits")
		self.decryption_iv = iv[0:self.decryption_key_size//8]


	def encrypt(self, data):
		return self.encryption_method(self, data)

	def decrypt(self, data):
		return self.decryption_method(self, data)


	##############
	# Algorithms #
	##############
	# TODO: 3des-cbc
	# TODO: blowfish-cbc
	# TODO: twofish-cbc

	def _aes_cbc_encrypt(self, data):
		if self.encryption_cipher is None:
			self.encryption_cipher = AES.new(self.encryption_key, AES.MODE_CBC, self.encryption_iv)
		return self.encryption_cipher.encrypt(data)
	def _aes_cbc_decrypt(self, data):
		if self.decryption_cipher is None:
			self.decryption_cipher = AES.new(self.decryption_key, AES.MODE_CBC, self.decryption_iv)
		return self.decryption_cipher.decrypt(data)

	# TODO: serpent-cbc
	# TODO: arcfour
	# TODO: idea-cbc
	# TODO: cast128-cbc

	def _no_encryption(self, data):
		return data
	def _no_decryption(self, data):
		return data


# List of algorithms and ref of their methods
# Higher prio = first
EncryptionHandler.algorithms = {
	"3des-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 8,
		"key_size": 112},
	"blowfish-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 8,
		"key_size": 128},
	"twofish-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 16,
		"key_size": 256},
	"twofish256-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 16,
		"key_size": 256},
	"twofish192-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 16,
		"key_size": 192},
	"twofish128-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 16,
		"key_size": 128},
	"aes256-cbc": {
		# TODO: Get the key length thing working with key generating
		"available": False,
		"priority": 998,
		"encryption_method": EncryptionHandler._aes_cbc_encrypt,
		"decryption_method": EncryptionHandler._aes_cbc_decrypt,
		"block_size": 16,
		"key_size": 256},
	"aes192-cbc": {
		# TODO: Get the key length thing working with key generating
		"available": False,
		"priority": 999,
		"encryption_method": EncryptionHandler._aes_cbc_encrypt,
		"decryption_method": EncryptionHandler._aes_cbc_decrypt,
		"block_size": 16,
		"key_size": 192},
	"aes128-cbc": {
		"available": True,
		"priority": 1000,
		"encryption_method": EncryptionHandler._aes_cbc_encrypt,
		"decryption_method": EncryptionHandler._aes_cbc_decrypt,
		"block_size": 16,
		"key_size": 128},
	"serpent256-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 16,
		"key_size": 256},
	"serpent192-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 16,
		"key_size": 192},
	"serpent128-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 16,
		"key_size": 128},
	"arcfour": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 1,
		"key_size": 128},
	"idea-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 8,
		"key_size": 128},
	"cast128-cbc": {
		"available": False,
		"priority": 0,
		"encryption_method": None,
		"decryption_method": None,
		"block_size": 8,
		"key_size": 128},
	"none": {
		"available": True,
		"priority": -1000,
		"encryption_method": EncryptionHandler._no_encryption,
		"decryption_method": EncryptionHandler._no_decryption,
		"block_size": 8,
		"key_size": 0}
}
