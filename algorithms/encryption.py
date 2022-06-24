"""
Encryption Algorithms
"""
from collections import OrderedDict


def enc_3des_cbc():
	"""
	REQUIRED
	three-key 3DES in CBC mode
	"""
	...

def enc_blowfish_cbc():
	"""
	OPTIONAL
	Blowfish in CBC mode
	"""
	...

def enc_twofish256_cbc():
	"""
	OPTIONAL
	Twofish in CBC mode, with a 256-bit key
	"""
	...

def enc_twofish_cbc():
	"""
	OPTIONAL
	alias for "twofish256-cbc" (this being retained for historical
	reasons)
	"""
	return enc_twofish256_cbc() # TODO: Add args when twofish256 done

def enc_twofish192_cbc():
	"""
	OPTIONAL
	Twofish with a 192-bit key
	"""
	...

def enc_twofish128_cbc():
	"""
	OPTIONAL
	Twofish with a 128-bit key
	"""
	...

def enc_aes256_cbc():
	"""
	OPTIONAL
	AES in CBC mode, with a 256-bit key
	"""
	...

def enc_aes192_cbc():
	"""
	OPTIONAL
	AES with a 192-bit key
	"""
	...

def enc_aes128_cbc():
	"""
	RECOMMENDED
	AES with a 128-bit key
	"""
	...

def enc_serpent256_cbc():
	"""
	OPTIONAL
	Serpent in CBC mode, with a 256-bit key
	"""
	...

def enc_serpent192_cbc():
	"""
	OPTIONAL
	Serpent with a 192-bit key
	"""
	...

def enc_serpent128_cbc():
	"""
	OPTIONAL
	Serpent with a 128-bit key
	"""
	...

def enc_arcfour():
	"""
	OPTIONAL
	the ARCFOUR stream cipher with a 128-bit key
	"""
	...

def enc_idea_cbc():
	"""
	OPTIONAL
	IDEA in CBC mode
	"""
	...

def enc_cast128_cbc():
	"""
	OPTIONAL
	CAST-128 in CBC mode
	"""
	...

def enc_none():
	"""
	OPTIONAL
	no encryption; NOT RECOMMENDED
	"""
	...


# List of algorithms, in order of priority.
algorithms = OrderedDict({
	"test_enc": None,
	"aes256-ctr": None,
	# "3des-cbc": enc_3des_cbc,
	# "blowfish-cbc": enc_blowfish_cbc,
	# "twofish256-cbc": enc_twofish256_cbc,
	# "twofish-cbc": enc_twofish_cbc,
	# "twofish192-cbc": enc_twofish192_cbc,
	# "twofish128-cbc": enc_twofish128_cbc,
	# "aes256-cbc": enc_aes256_cbc,
	# "aes192-cbc": enc_aes192_cbc,
	# "aes128-cbc": enc_aes128_cbc,
	# "serpent256-cbc": enc_serpent256_cbc,
	# "serpent192-cbc": enc_serpent192_cbc,
	# "serpent128-cbc": enc_serpent128_cbc,
	# "arcfour": enc_arcfour,
	# "idea-cbc": enc_idea_cbc,
	# "cast128-cbc": enc_cast128_cbc,
	# "none": enc_none,
})
