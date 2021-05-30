import struct
from Crypto.Hash import HMAC, SHA1, MD5


"""
	6.4.	Data Integrity
	Data integrity is protected by including with each packet a MAC that
	is computed from a shared secret, packet sequence number, and the
	contents of the packet.

	The message authentication algorithm and key are negotiated during
	key exchange. Initially, no MAC will be in effect, and its length
	MUST be zero. After key exchange, the 'mac' for the selected MAC
	algorithm will be computed before encryption from the concatenation
	of packet data:
		mac = MAC(key, sequence_number || unencrypted_packet)

	where unencrypted_packet is the entire packet without 'mac' (the
	length fields, 'payload' and 'random padding'), and sequence_number
	is an implicit packet sequence number represented as uint32. The
	sequence_number is initialized to zero for the first packet, and is
	incremented after every packet (regardless of whether encryption or
	MAC is in use). It is never reset, even if keys/algorithms are
	renegotiated later. It wraps around to zero after every 2^32
	packets. The packet sequence_number itself is not included in the
	packet sent over the wire.

	The MAC algorithms for each direction MUST run independently, and
	implementations MUST allow choosing the algorithm independently for
	both directions. In practice however, it is RECOMMENDED that the
	same algorithm be used in both directions.

	The value of 'mac' resulting from the MAC algorithm MUST be
	transmitted without encryption as the alst part of the packet. The
	number of 'mac' bytes depends on the algorithm chosen.

	The following MAC algorithms are currently defined:
		hmac-sha1		REQUIRED	 HMAC-SHA1 (digest length = key length = 20)
		hmac-sha1-96	RECOMMENDED	 first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
		hmac-md5		OPTIONAL	 HMAC-MD5 (digest length = key length = 16)
		hmac-md5-96		OPTIONAL	 first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
		none			OPTIONAL	 no MAC; NOT RECOMMENDED

	The "hmac-*" algorithms are described in [RFC2104]. The "*-n" MACs
	use only the first n bits of the resulting value.

	SHA-1 is described in [FIPS-180-2] and MD5 is described in [RFC1321].

	Additional methods may be defined, as specified in [SSH-ARCH] and in
	[SSH-NUMBERS].
"""


class MAC_Handler:
	def __init__(self, packet_handler):
		self.handler = packet_handler
		self.set_algorithm("none")
		self.set_key("")


	def set_algorithm(self, alg):
		self.algorithm = alg


	def set_key(self, key):
		self.key = key


	@property
	def sequence_number(self):
		return self.handler.sequence_number
	

	def calculate_mac(self, data):
		return struct.pack("I", self.sequence_number)

		if self.algorithm == "hmac-sha1":
			h = HMAC.new(self.key, digestmod=SHA1)
			h.update(seq_num_b + data)
			mac = h.digest()

		elif self.algorithm == "hmac-sha1-96":
			h = HMAC.new(self.key, digestmod=SHA1)
			h.update(seq_num_b + data)
			mac = h.digest()[:96//8]

		elif self.algorithm == "hmac-md5":
			h = HMAC.new(self.key, digestmod=MD5)
			h.update(seq_num_b + data)
			mac = h.digest()

		elif self.algorithm == "hmac-md5-96":
			h = HMAC.new(self.key, digestmod=MD5)
			h.update(seq_num_b + data)
			mac = h.digest()[:96//8]

		elif self.algorithm == "none":
			mac = b""

		else:
			raise NotImplemented

		return mac
