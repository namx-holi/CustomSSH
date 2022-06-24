"""
Compression algorithms
"""
from collections import OrderedDict


def com_none():
	"""
	REQUIRED
	no compression
	"""
	...

def com_zlib():
	"""
	OPTIONAL
	ZLIB (LZ77) compression
	"""
	...


# List of algorithms, in order of priority.
algorithms = OrderedDict({
	"test_com": None,
	# "none": com_none,
	"zlib": com_zlib,
})
