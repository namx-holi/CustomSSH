

"""
	6.2.	Compression
	If compression has been negotiated, the 'payload' field (and only it)
	will be compressed during the negotiated algorithm.  The
	'packet_length' field and 'mac' will be computed from the compressed
	payload.  Encryption will be done after compression.

	Compression MAY be stateful, depending on the method.  Compression
	MUST be independent for each direction, and implementations MUST
	allow independent choosing of the algorithm for each direction.  In
	practice however, it is RECOMMENDED that the compression method be
	the same in both directions.

	The following compression methods are currently defined:
		none	REQUIRED	no compression
		zlib	OPTIONAL	ZLIB (LZ77) compression

	The "zlib" compression is described in [RFC1950] and in [RFC1951].
	The compression context is initialized after each key exchange, and
	is passed from one packet to the next, with only a partial flush
	being performed at the end of each packet.  A partial flush means
	that the current compressed block is ended and all data will be
	output.  If the current block is not a stored block, one or more
	empty blocks are added after the current block to ensure that there
	are at least 8 bits, counting from the start of the end-of-block code
	of the current block to the end of the packet payload.

	Additional methods may be defined as specified in [SSH-ARCH] and
	[SSH-NUMBERS]
"""


class CompressionHandler:
	def __init__(self, packet_handler):
		self.handler = packet_handler
		self.set_algorithm("none")


	def set_algorithm(self, alg):
		self.algorithm = alg


	def compress(self, payload):
		if self.algorithm == "zlib":
			raise NotImplemented

		elif self.algorithm == "none":
			return payload

		else:
			raise NotImplemented
