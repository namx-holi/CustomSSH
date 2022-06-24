"""
MAC Algorithms
"""
from collections import OrderedDict


def mac_hmac_sha1():
	"""
	REQUIRED
	HMAC-SHA1 (digest length = key length = 20)
	"""
	...

def mac_hmac_sha1_96():
	"""
	RECOMMENDED
	first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
	"""
	...

def mac_hmac_md5():
	"""
	OPTIONAL
	HMAC-MD5 (digest length = key length = 16)
	"""
	...

def mac_hmac_md5_96():
	"""
	OPTIONAL
	first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
	"""
	...

def mac_none():
	"""
	OPTIONAL
	no MAC; NOT RECOMMENDED
	"""
	...


# List of algorithms, in order of priority.
algorithms = OrderedDict({
	"test_mac": None,
	"hmac-sha2-256": None,
	# "hmac-sha1": mac_hmac_sha1,
	# "hmac-sha1-96": mac_hmac_sha1_96,
	# "hmac-md5": mac_hmac_md5,
	# "hmac-md5-96": mac_hmac_md5_96,
	# "none": mac_none,
})
