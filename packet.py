import math
from os import urandom as os_urandom
import struct

from mac_handler import MAC_Handler
from compression_handler import CompressionHandler
from encryption_handler import EncryptionHandler


"""
	6.	Binary Packet Control
	Each packet is in the following format:
		uint32		packet_length
		byte		padding_length
		byte[n1]	payload; n1 = packet_length - padding_length - 1
		byte[n2]	random padding; n2 = padding_length
		byte[m]		mac (Message Authentication Code - MAC); m = mac_length

	packet_length
		The length of the packet in bytes, not including 'mac' or the
		'packet_length' field itself.

	padding_length
		Length of 'random padding' (bytes).

	payload
		The useful contents of the packet.  If compression has been
		negotiated, this field is compressed.  Initially, compression
		MUST be "none".

	random padding
		Arbitrary-length padding, such that the total length of
		(packet_length || padding_length || payload || random padding)
		is a multiple of the cipher block size or 8, whichever is
		larger.  There MUST be at least four bytes of padding.  The
		padding SHOULD consist of random bytes.  The maximum amount of
		padding is 255 bytes.

	mac
		Message Authentication Code.  If message authentication has
		been negotiated, this field contains the MAC bytes.  Initially,
		the MAC algorithm MUST be "none".

	Note that the length of the concatenation of 'packet_length',
	'padding_length', 'payload', and 'random padding' MUST be a multiple
	of the cipher block size or 8, whichever is larger.  This constraint
	MUST be enforced, even when using stream ciphers.  Note that the
	'packet_length' field is also encrypted, and processing it requres
	special care when sending or receiving packets.  Also note that the
	insertion of variable amounts of 'random padding' may help thwart
	traffic analysis.

	The minimum size of a packet is 16 (or the cipher block size,
	whichever is larger) bytes (plus 'mac').  Implementations SHOULD
	decrypt the length after receiving the first 8 (or cipher block size,
	whichever is larger) bytes of a packet.


	6.1.	Maximum Packet Length
	All implementations MUST be able to process packets with an
	uncompressed payload length of 32768 bytes or less and a total packet
	size of 35000 bytes or less (including 'packet_length',
	'padding_length', 'payload', 'random padding', and 'mac').  The
	maximum of 35000 bytes is an arbitrarily chosen value that is larger
	than the uncompressed length noted above. Implementations SHOULD
	support longer packets, where they might be needed.  For example, if
	an implementation wants to send a very large number of certificates,
	the larger packets MAY be sent if the identification string indicates
	that the other party is able to process them.  However,
	implementations SHOULD check that the packet length is reasonable in
	order for the implementation to avoid denial of service and/or buffer
	overflow attacks.
"""


class PacketHandler:

	def __init__(self):
		self.compression_handler = CompressionHandler(self)
		self.mac_handler = MAC_Handler(self)
		self.encryption_handler = EncryptionHandler(self)

		# Sequence number always starts at zero
		self._sequence_number = 0


	def set_mac_alg(self, alg):
		# TODO: Check if algorithm one of the valid ones?
		self.mac_handler.set_algorithm(alg)
	def set_mac_key(self, key):
		self.mac_handler.set_key(key)
	def set_compression_alg(self, alg):
		# TODO: Check if algorithm one of the valid ones?
		self.compression_handler.set_algorithm(alg)
	def set_encryption_alg(self, alg):
		# TODO: Check if algorithm one of the valid ones?
		self.encryption_handler.set_algorithm(alg)
	def set_encryption_key(self, key):
		self.encryption_handler.set_key(key)


	@property
	def block_size(self):
		return self.encryption_handler.block_size


	@property
	def sequence_number(self):
		"""
		sequence_number is an implicit packet sequence number
		represented as uint32. The sequence_number is initialized
		to zero for the first packet, and is incremented after
		every packet (regardless of whether encryption or MAC is
		in use). It is never reset, even if keys/algorithms are
		renegotiated later. It wraps around to zero after every
		2^32 packets. THe packet sequence number itself is not
		included in the packet sent over the wire.
		"""
		return self._sequence_number


	def increment_sequence_number(self):
		# Increment the sequence number. Wrap at 2**32
		self._sequence_number += 1
		if self._sequence_number == 2**32:
			self._sequence_number = 0


	def new_packet(self, payload):
		p = Packet(self, payload)
		return p


	def compile_packet(self, packet):
		"""
		From 6. Binary Packet Protocol:
		Each packet is in the following format:
			uint32		packet_length
			byte		padding_length
			byte[n1]	payload; n1 = packet_length - padding_length - 1
			byte[n2]	random padding; n2 = padding_length
			byte[m]		mac (Message Authentication Code - MAC); m = mac_length

		From 6.2. Compression:
		If compression has been negotiated, the 'payload' field (and only it)
		will be compressed during the negotiated algorithm.  The
		'packet_length' field and 'mac' will be computed from the compressed
		payload.  Encryption will be done after compression.

		From 6.4. Data Integrity
		After key exchange, the 'mac' for the selected MAC algorithm will be
		computed before encryption from the concatenation of packet data:
			mac = MAC(key, sequence_number || unencrypted_packet)

		From 6.3. Encryption
		An encryption algorithm and key will be negotiated during the key
		exchange.  When encryption is in effect, the packet length, padding
		length, payload, and padding fields of each packet MUST be encrypted
		with the given algorithm.
		"""

		# Start off with compressing payload
		payload_b = self.compression_handler.compress(packet.payload)

		# Next up, we can calculate the desired padding
		block_size = self.block_size
		unpadded_length = (
			4 # packet length is int32, always 4 bytes
			+ 1 # padding_length is stored in 1 byte
			+ len(payload_b))
		desired_length = max(
			16, # Minimum packet size is 16 bytes
			math.ceil(unpadded_length/block_size) * block_size)
		padding_length = desired_length - unpadded_length
		if padding_length < 4:
			padding_length = padding_length + block_size
		padding_length_b = struct.pack("B", padding_length)

		# And from that we know the packet length
		packet_length = unpadded_length + padding_length
		packet_length_b = struct.pack("I", packet_length)

		# We can calculate the padding
		random_padding_b = os_urandom(padding_length)

		complete_packet = (
			packet_length_b
			+ padding_length_b
			+ payload_b
			+ random_padding_b)

		# We can then calculate the mac
		mac = self.mac_handler.calculate_mac(complete_packet)

		# And encrypt what needs to be encrypted
		encrypted_packet = self.encryption_handler.encrypt(complete_packet)

		# And return the bytes!
		return encrypted_packet + mac


		# uint32		packet_length
		packet_length = packet.calc_packet_length()
		packet_length_b = struct.pack("I", packet_length)

		# byte		padding_length
		padding_length = packet.calc_padding_length()
		padding_length_b = struct.pack("B", padding_length)

		# byte[n1]	payload; n1 = packet_length - padding_length - 1
		...

		# byte[n2]	random padding; n2 = padding_length
		...

		# byte[m]		mac (Message Authentication Code - MAC); m = mac_length
		...








class Packet:

	def __init__(self, handler, payload):
		self.handler = handler

		if isinstance(payload, bytes):
			self.payload = payload
		else:
			# TODO: Ensure that utf-8 is enough for this?
			self.payload = payload.encode("utf-8")


	def compile(self):
		return self.handler.compile_packet(self)





if __name__ == "__main__":
	print("Initialising a packet handler")
	packet_handler = PacketHandler()

	compression_alg = "none"
	print(f"  Setting compression to {compression_alg}")
	packet_handler.set_compression_alg("none")

	mac_alg = "hmac-sha1"
	mac_key = b"1234567890123456"
	print(f"  Setting MAC to {mac_alg} with key {mac_key}")
	packet_handler.set_mac_alg(mac_alg)
	packet_handler.set_mac_key(mac_key)

	enc_alg = "aes128-cbc"
	enc_key = b"7890123456789012"
	print(f"  Setting encryption to {enc_alg} with key {enc_key}")
	packet_handler.set_encryption_alg(enc_alg)
	packet_handler.set_encryption_key(enc_key)

	payload = b"Hello, World!"
	print(f"Creating packet of payload:{payload}")
	p = packet_handler.new_packet(payload)
	p_b = p.compile()

	print(f"Result is:{p_b}")
