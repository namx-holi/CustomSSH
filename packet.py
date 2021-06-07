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
		self.encryption_handler = EncryptionHandler(self)
		self.mac_handler = MAC_Handler(self)
		self.compression_handler = CompressionHandler(self)

		# Sequence number always starts at zero
		self._incoming_sequence_number = 0
		self._outgoing_sequence_number = 0

		# Used to skip resetting algs when generating new keys
		self.algorithms_set = False


	def prepare_algorithms(self,
		enc_c_to_s, enc_s_to_c,
		mac_c_to_s, mac_s_to_c,
		com_c_to_s, com_s_to_c
	):
		self.encryption_handler.prepare_decryption_algorithm(enc_c_to_s)
		self.encryption_handler.prepare_encryption_algorithm(enc_s_to_c)
		self.mac_handler.prepare_check_algorithm(mac_c_to_s)
		self.mac_handler.prepare_authenticate_algorithm(mac_s_to_c)

		# TODO: Handle com_c_to_s
		self.compression_handler.prepare_algorithm(com_s_to_c)
	def set_prepared_algorithms(self):
		if self.algorithms_set:
			return

		self.encryption_handler.set_prepared_decryption_algorithm()
		self.encryption_handler.set_prepared_encryption_algorithm()
		self.mac_handler.set_prepared_check_algorithm()
		self.mac_handler.set_prepared_authenticate_algorithm()

		# TODO: Handle com_c_to_s
		self.compression_handler.set_prepared_algorithm()

		self.algorithms_set = True


	def set_keys(self,
		iv_c_to_s, iv_s_to_c,
		enc_c_to_s, enc_s_to_c,
		mac_c_to_s, mac_s_to_c
	):
		self.encryption_handler.set_decryption_iv(iv_c_to_s)
		self.encryption_handler.set_encryption_iv(iv_s_to_c)
		self.encryption_handler.set_decryption_key(enc_c_to_s)
		self.encryption_handler.set_encryption_key(enc_s_to_c)

		# TODO: Handle mac stuff
		self.mac_handler.set_check_key(mac_c_to_s)
		self.mac_handler.set_authenticate_key(mac_s_to_c)



	# def set_mac_alg(self, alg):
	# 	self.mac_handler.set_algorithm(alg)
	# def set_mac_key(self, key):
	# 	self.mac_handler.set_key(key)
	# def set_compression_alg(self, alg):
	# 	self.compression_handler.set_algorithm(alg)
	# def set_encryption_alg(self, alg):
	# 	self.encryption_handler.set_encryption_algorithm(alg)
	# def set_encryption_key(self, key):
	# 	self.encryption_handler.set_encryption_key(key)
	# def set_decryption_alg(self, alg):
	# 	self.encryption_handler.set_decryption_algorithm(alg)
	# def set_decryption_key(self, key):
	# 	self.encryption_handler.set_decryption_key(key)
	# def set_decryption_iv(self, iv):
	# 	self.encryption_handler.set_decryption_iv(iv)


	@property
	def encryption_block_size(self):
		return self.encryption_handler.encryption_block_size
	@property
	def decryption_block_size(self):
		return self.encryption_handler.decryption_block_size
	@property
	def mac_digest_length(self):
		return self.mac_handler.digest_length


	@property
	def outgoing_sequence_number(self):
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
		return self._outgoing_sequence_number
	@property
	def incoming_sequence_number(self):
		return self._incoming_sequence_number


	def increment_incoming_sequence_number(self):
		# Increment the sequence number. Wrap at 2**32
		self._incoming_sequence_number += 1
		if self._incoming_sequence_number == 2**32:
			self._incoming_sequence_number = 0
	def increment_outgoing_sequence_number(self):
		# Increment the sequence number. Wrap at 2**32
		self._outgoing_sequence_number += 1
		if self._outgoing_sequence_number == 2**32:
			self._outgoing_sequence_number = 0


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

		# Calculate the padding length
		block_size = self.encryption_block_size
		unpadded_len = len(payload_b) + 1 # +1 for padding length byte
		desired_len = max( # Should be a multiple of block size
			16, # Minimum packet size is 16 bytes
			math.ceil(unpadded_len/block_size) * block_size)
		padding_len = desired_len - unpadded_len - 4 # -4 for packet len uint32
		if padding_len < 4: # Minimum padding length is 4
			padding_len += block_size
		padding_len_b = struct.pack(">B", padding_len)

		# Calculate the packet length
		packet_len = len(payload_b) + padding_len + 1
		packet_len_b = struct.pack(">I", packet_len)

		# Generate the padding bytes. Should be random to reduce
		#  information leaked through traffic analysis when encrypted
		random_padding_b = os_urandom(padding_len)

		# Join all the bytes together!
		complete_packet = (
			packet_len_b
			+ padding_len_b
			+ payload_b
			+ random_padding_b)

		# Generate the mac
		mac = self.mac_handler.calculate_mac(complete_packet)

		# Encrypt the packet. Since it's a block cipher the length can
		#  be read in the first block by itself so the len can be
		#  encrypted too.
		encrypted_packet = self.encryption_handler.encrypt(complete_packet)

		# Increment our sequence number
		self.increment_outgoing_sequence_number()

		# And return our bytes!
		return encrypted_packet + mac


	# TODO: Get rid of, or rewrite
	def read_packet(self, raw):
		# # Read from conn...?
		# # TODO: How to handle this?
		# raw = conn.read()

		# TODO:
		"""
		Implementations SHOULD
		decrypt the length after receiving the first 8 (or cipher block size,
		whichever is larger) bytes of a packet.
		"""

		# First separate the mac and the packet
		if self.mac_handler.digest_length == 0:
			# Need to separate this as otherwise we get [-0:] which == [0:]
			encrypted_packet = raw
			mac = b""
		else:
			encrypted_packet = raw[:-self.mac_handler.digest_length]
			mac = raw[-self.mac_handler.digest_length:]

		# Decrypt the packet
		complete_packet = self.encryption_handler.decrypt(encrypted_packet)

		# Verify the mac
		valid = self.mac_handler.verify_mac(complete_packet, mac)
		print("Mac was valid? :", valid)

		# Increment their sequence number
		self.increment_incoming_sequence_number()

		# Read the packet length and padding lengths
		packet_length = struct.unpack(">I", complete_packet[:4])[0]
		padding_length = struct.unpack(">B", complete_packet[4:5])[0]

		# Strip the lengths and padding from the payload
		payload_compressed = complete_packet[5:-padding_length]

		# And decompress
		payload = self.compression_handler.decompress(payload_compressed)

		return payload


	def read_packet_from_conn(self, conn):
		block_size = self.decryption_block_size

		# Read the first block for packet length
		first_block_encrypted = conn.recv(block_size)
		if first_block_encrypted == b"":
			return None

		first_block = self.encryption_handler.decrypt(first_block_encrypted)
		packet_len = struct.unpack(">I", first_block[:4])[0]

		# Read the remaining packet
		remaining_to_read = packet_len - (block_size - 4)
		# Above is to compensate that we read part of the packet already through
		# the first block
		remaining_packet_encrypted = conn.recv(remaining_to_read)
		remaining_packet = self.encryption_handler.decrypt(remaining_packet_encrypted)
		full_packet = first_block + remaining_packet

		# Read the mac and verify it
		mac = conn.recv(self.mac_digest_length)
		valid = self.mac_handler.verify_mac(full_packet, mac)
		if not valid:
			print("MAC WAS NOT VALID????")

		# Read the padding length
		padding_length = struct.unpack(">B", full_packet[4:5])[0]

		# Extract the compressed payload and decompress
		payload_compressed = full_packet[5:-padding_length]
		payload = self.compression_handler.decompress(payload_compressed)

		return payload



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


	def __repr__(self):
		return f"<Packet: {self.payload}>"



def test1():
	print("Initialising a packet handler")
	packet_handler = PacketHandler()

	compression_alg = "none"
	print(f"  Setting compression to {compression_alg}")
	packet_handler.set_compression_alg("none")

	mac_alg = "hmac-sha1"
	mac_key = b"12345678901234567890"
	print(f"  Setting MAC to {mac_alg} with key {mac_key}")
	packet_handler.set_mac_alg(mac_alg)
	packet_handler.set_mac_key(mac_key)

	enc_alg = "aes128-cbc"
	enc_key = b"7890123456789012"
	print(f"  Setting encryption to {enc_alg} with key {enc_key}")
	packet_handler.set_encryption_alg(enc_alg)
	packet_handler.set_encryption_key(enc_key)
	packet_handler.set_decryption_alg(enc_alg)
	packet_handler.set_decryption_key(enc_key)

	payload = b"Hello, World!"
	print(f"Creating packet of payload:{payload}")
	p = packet_handler.new_packet(payload)
	p_b = p.compile()

	print(f"Result is:{p_b}")

	print("")
	print("Attempting to decrypt")
	packet_handler.set_decryption_iv(packet_handler.encryption_handler.encryption_cipher.iv)
	p = packet_handler.read_packet(p_b)
	print(p)


def test2():
	h = PacketHandler()

	print("kex_client_data")
	# Overall length: 1592
	# Packet Length:  1588
	# Padding Length: 6
	data_length = 1581 # 1587 - 6
	kex_client_data = b"\xaa"*data_length
	p = h.new_packet(kex_client_data)
	p.compile()

	print("kex_server_data")
	# Overall length: 1080
	# Packet Length:  1076
	# Padding Length: 6
	data_length = 1069 # 1075 - 6
	kex_server_data = b"\xaa"*data_length
	p = h.new_packet(kex_server_data)
	p.compile()

	print("dh_group_exchange_request")
	# Overall length: 24
	# Packet Length:  20
	# Padding Length: 6
	data_length = 13 # 19 - 6
	dh_group_exchange_request = b"\xaa"*data_length
	p = h.new_packet(dh_group_exchange_request)
	p.compile()

	print("dh_group_exchange_group")
	# Overall length: 280
	# Packet Length:  276
	# Padding Length: 8
	data_length = 267 # 275 - 8
	dh_group_exchange_group = b"\xaa"*data_length
	p = h.new_packet(dh_group_exchange_group)
	p.compile()

	print("dh_group_exchange_init")
	# Overall length: 272
	# Packet Length:  268
	# Padding Length: 6
	data_length = 261 # 267 - 6
	dh_group_exchange_init = b"\xaa"*data_length
	p = h.new_packet(dh_group_exchange_init)
	p.compile()

	print("dh_group_exchange_reply")
	# Overall length: 832
	# Packet Length:  828
	# Padding Length: 8
	data_length = 819 # 827 - 8
	dh_group_exchange_reply = b"\xaa"*data_length
	p = h.new_packet(dh_group_exchange_reply)
	p.compile()

	print("new_keys_server")
	# Overall length: 16
	# Packet Length:  12
	# Padding Length: 10
	data_length = 1 # 11 - 10
	new_keys_server = b"\xaa"*data_length
	p = h.new_packet(new_keys_server)
	p.compile()

	print("new_keys_client")
	# Overall length: 16
	# Packet Length:  12
	# Padding Length: 10
	data_length = 1 # 11 - 10
	new_keys_client = b"\xaa"*data_length
	p = h.new_packet(new_keys_client)
	p.compile()




if __name__ == "__main__":
	# test1()
	test2()


