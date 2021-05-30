from Crypto.Cipher import AES

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


class EncryptionHandler:

	def __init__(self, packet_handler):
		self.handler = packet_handler
		self.set_algorithm("none")
		self.set_key("")


	def set_algorithm(self, alg):
		alg = self.algorithms.get(alg, None)
		if alg is None:
			raise NotImplemented("algorithm not handled")

		method = alg.get("method")
		if method is None:
			raise NotImplemented("algorithm method not implemented")

		self.encryption_method = method
		self.block_size = alg.get("block_size")
		self.key_size = alg.get("key_size")

		# Reset the cipher object
		self.cipher = None


	def set_key(self, key):
		if len(key)*8 != self.key_size:
			raise Exception(f"Key size needs to be {self.key_size} bits")

		self.key = key


	def encrypt(self, data):
		return self.encryption_method(self, data)


	##############
	# Algorithms #
	##############
	# TODO: 3des-cbc
	# TODO: blowfish-cbc
	# TODO: twofish-cbc

	def _aes_cbc(self, data):
		if self.cipher is None:
			self.cipher = AES.new(self.key, AES.MODE_CBC)
		return self.cipher.encrypt(data)

	# TODO: serpent-cbc
	# TODO: arcfour
	# TODO: idea-cbc
	# TODO: cast128-cbc

	def _no_encryption(self, data):
		return data


# List of algorithms and ref of their methods
EncryptionHandler.algorithms = {
	"3des-cbc": {
		"method": None,
		"block_size": 8,
		"key_size": 112},
	"blowfish-cbc": {
		"method": None,
		"block_size": 8,
		"key_size": 128},
	"twofish-cbc": {
		"method": None,
		"block_size": 16,
		"key_size": 256},
	"twofish256-cbc": {
		"method": None,
		"block_size": 16,
		"key_size": 256},
	"twofish192-cbc": {
		"method": None,
		"block_size": 16,
		"key_size": 192},
	"twofish128-cbc": {
		"method": None,
		"block_size": 16,
		"key_size": 128},
	"aes256-cbc": {
		"method": EncryptionHandler._aes_cbc,
		"block_size": 16,
		"key_size": 256},
	"aes192-cbc": {
		"method": EncryptionHandler._aes_cbc,
		"block_size": 16,
		"key_size": 192},
	"aes128-cbc": {
		"method": EncryptionHandler._aes_cbc,
		"block_size": 16,
		"key_size": 128},
	"serpent256-cbc": {
		"method": None,
		"block_size": 16,
		"key_size": 256},
	"serpent192-cbc": {
		"method": None,
		"block_size": 16,
		"key_size": 192},
	"serpent128-cbc": {
		"method": None,
		"block_size": 16,
		"key_size": 128},
	"arcfour": {
		"method": None,
		"block_size": 1,
		"key_size": 128},
	"idea-cbc": {
		"method": None,
		"block_size": 8,
		"key_size": 128},
	"cast128-cbc": {
		"method": None,
		"block_size": 8,
		"key_size": 128},
	"none": {
		"method": EncryptionHandler._no_encryption,
		"block_size": 8,
		"key_size": 0}
}
