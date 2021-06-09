import struct
from Crypto.Hash import HMAC, SHA1, MD5

from helpers import GenericHandler

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

# TODO: Split mac to be independent. Currently it is not.


class MAC_Handler(GenericHandler):

	def __init__(self, packet_handler):
		self.handler = packet_handler
		self.set_authenticate_algorithm("none")
		self.set_check_algorithm("none")


	def prepare_authenticate_algorithm(self, alg):
		self.prepared_authenticate_algorithm = alg
	def set_prepared_authenticate_algorithm(self):
		self.set_authenticate_algorithm(self.prepared_authenticate_algorithm)
		self.prepared_authenticate_algorithm = None

	def prepare_check_algorithm(self, alg):
		self.prepared_check_algorithm = alg
	def set_prepared_check_algorithm(self):
		self.set_check_algorithm(self.prepared_check_algorithm)
		self.prepared_check_algorithm = None


	def set_authenticate_algorithm(self, alg):
		alg = self.algorithms.get(alg, None)
		if alg is None:
			raise Exception(f"algorithm {alg} not handled")
		
		available = alg.get("available")
		if not available:
			raise Exception(f"algorithm {alg} not available")

		self.auth_method = alg.get("auth_method")
		self.auth_digest_length = alg.get("digest_length")
		self.auth_key_size = alg.get("key_size")

	def set_check_algorithm(self, alg):
		alg = self.algorithms.get(alg, None)
		if alg is None:
			raise Exception(f"algorithm {alg} not handled")
		
		available = alg.get("available")
		if not available:
			raise Exception(f"algorithm {alg} not available")

		self.check_method = alg.get("check_method")
		self.check_digest_length = alg.get("digest_size")
		self.check_key_size = alg.get("key_size")


	def set_authenticate_key(self, key):
		if len(key) < self.auth_key_size:
			raise Exception(f"Auth key size needs to be {self.auth_key_size} bytes")
		self.auth_key = key[0:self.auth_key_size]

	def set_check_key(self, key):
		if len(key) < self.check_key_size:
			raise Exception(f"Check key size needs to be {self.check_key_size} bytes")
		self.check_key = key[0:self.check_key_size]


	@property
	def incoming_sequence_number(self):
		return self.handler.incoming_sequence_number

	@property
	def outgoing_sequence_number(self):
		return self.handler.outgoing_sequence_number
	

	def calculate_mac(self, data):
		return self.auth_method(self, data)

	def verify_mac(self, data, mac):
		return self.check_method(self, data, mac)


	##############
	# Algorithms #
	##############
	def _hmac_sha1(self, data):
		seq_num_b = struct.pack(">I", self.outgoing_sequence_number)
		h = HMAC.new(self.auth_key, digestmod=SHA1)
		h.update(seq_num_b + data)
		return h.digest()
	def _hmac_sha1_check(self, data, mac):
		seq_num_b = struct.pack(">I", self.incoming_sequence_number)
		h = HMAC.new(self.check_key, digestmod=SHA1)
		h.update(seq_num_b + data)
		return h.digest() == mac

	def _hmac_sha1_96(self, data):
		seq_num_b = struct.pack(">I", self.outgoing_sequence_number)
		h = HMAC.new(self.auth_key, digestmod=SHA1)
		h.update(seq_num_b + data)
		return h.digest()[:96//8]
	def _hmac_sha1_96_check(self, data, mac):
		seq_num_b = struct.pack(">I", self.incoming_sequence_number)
		h = HMAC.new(self.check_key, digestmod=SHA1)
		h.update(seq_num_b + data)
		return h.digest()[:96//8] == mac

	def _hmac_md5(self, data):
		seq_num_b = struct.pack(">I", self.outgoing_sequence_number)
		h = HMAC.new(self.auth_key, digestmod=MD5)
		h.update(seq_num_b + data)
		return h.digest()
	def _hmac_md5_check(self, data, mac):
		seq_num_b = struct.pack(">I", self.incoming_sequence_number)
		h = HMAC.new(self.check_key, digestmod=MD5)
		h.update(seq_num_b + data)
		return h.digest() == mac


	def _hmac_md5_96(self, data):
		seq_num_b = struct.pack("I", self.outgoing_sequence_number)
		h = HMAC.new(self.auth_key, digestmod=MD5)
		h.update(seq_num_b + data)
		return h.digest()[:96//8]
	def _hmac_md5_96_check(self, data, mac):
		seq_num_b = struct.pack("I", self.incoming_sequence_number)
		h = HMAC.new(self.check_key, digestmod=MD5)
		h.update(seq_num_b + data)
		return h.digest()[:96//8] == mac


	def _no_mac(self, data):
		return b""
	def _no_mac_check(self, data, mac):
		return True


# List of algorithms and ref of their methods
MAC_Handler.algorithms = {
	"hmac-sha1": {
		# TODO: Get working. It doesn't generate the correct MAC.
		"available": False,
		"priority": 1000,
		"auth_method": MAC_Handler._hmac_sha1,
		"check_method": MAC_Handler._hmac_sha1_check,
		"digest_length": 20,
		"key_size": 20},
	"hmac-sha1-96": {
		# TODO: Get working. It doesn't generate the correct MAC.
		"available": False,
		"priority": 999,
		"auth_method": MAC_Handler._hmac_sha1_96,
		"check_method": MAC_Handler._hmac_sha1_96_check,
		"digest_length": 12,
		"key_size": 20},
	"hmac-md5": {
		"available": True,
		"priority": 100,
		"auth_method": MAC_Handler._hmac_md5,
		"check_method": MAC_Handler._hmac_md5_check,
		"digest_length": 16,
		"key_size": 16},
	"hmac-md5-96": {
		# TODO: Get working. It doesn't generate the correct MAC.
		"available": False,
		"priority": 99,
		"auth_method": MAC_Handler._hmac_md5_96,
		"check_method": MAC_Handler._hmac_md5_96_check,
		"digest_length": 12,
		"key_size": 16},
	"none": {
		"available": True,
		"priority": -1000,
		"auth_method": MAC_Handler._no_mac,
		"check_method": MAC_Handler._no_mac_check,
		"digest_length": 0,
		"key_size": 0}
}