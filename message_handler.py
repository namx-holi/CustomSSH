
import math
import struct
from os import urandom

from messages import SSH_MSG


class MessageHandler:
	"""
	Packet format, described in RFC4253, Section 6.

	uint32 packet_length
		The length of the packet in bytes, not including 'mac' or the
		'packet_length' field itself.

	byte padding_length
		Length of 'random padding' (bytes)

	payload
		The useful contents of the packet. If compression has been
		negotiated, this field is compressed. Initially, compression
		MUST be "none".

	random padding
		Arbitrary-length padding, such that the total length of
		(packet_length || padding_length || payload || random padding)
		is a multiple of the cipher block size or 8, whichever is
		larger. There MUST be at least four bytes of padding. The
		padding SHOULD consist of random bytes. The maximum amount of
		padding is 255 bytes.

	mac
		Message Authentication Code. If message authentication has been
		negotiated, this field contains the MAC bytes. Initially, the
		MAC algorithm MUST be "none".
	"""

	def __init__(self, conn):
		self.conn = conn

		# TODO: Handle wrapping of the seq numbers
		self._client_sequence_number = 0
		self._server_sequence_number = 0

		# Unencrypted traffic uses a block size of 8
		# self.client_block_size = 8 
		# self.server_block_size = 8

		# Algorithms being used. If None, they are ignored
		self.encryption_algo_c_to_s = None
		self.encryption_algo_s_to_c = None
		self.mac_algo_c_to_s = None
		self.mac_algo_s_to_c = None
		self.compression_algo_c_to_s = None
		self.compression_algo_s_to_c = None

		# # Encryption and integrity keys expected lengths in bytes
		# self.initial_iv_client_len     = 16 # aes128-cbc
		# self.initial_iv_server_len     = 16 # aes128-cbc
		# self.encryption_key_client_len = 16 # aes128-cbc
		# self.encryption_key_server_len = 16 # aes128-cbc
		# self.integrity_key_client_len  = 20 # hmac-sha1
		# self.integrity_key_server_len  = 20 # hmac-sha1

		# # Sizes of MACs
		# self.integrity_hash_client_len = 20 # hmac-sha1
		# self.integrity_hash_server_len = 20 # hmac-sha1

		# # Encryption and integrity keys
		# self.initial_iv_client     = None
		# self.initial_iv_server     = None
		# self.encryption_key_client = None
		# self.encryption_key_server = None
		# self.integrity_key_client  = None
		# self.integrity_key_server  = None

		# # Instances of ciphers are stored after initialised
		# self.encryption_cipher_client = None
		# self.encryption_cipher_server = None

		# self.encryption_enabled = False
		# self.mac_enabled = False


	# Wrappers for algorithms
	@property
	def client_block_size(self):
		if self.encryption_algo_c_to_s is None:
			return 8
		return self.encryption_algo_c_to_s.iv_length
	@property
	def server_block_size(self):
		if self.encryption_algo_s_to_c is None:
			return 8
		return self.encryption_algo_s_to_c.iv_length
	def decrypt(self, data):
		if self.encryption_algo_c_to_s is None:
			return data
		return self.encryption_algo_c_to_s.decrypt(data)
	def encrypt(self, data):
		if self.encryption_algo_s_to_c is None:
			return data
		return self.encryption_algo_s_to_c.encrypt(data)
	def verify_mac(self, data):
		if self.mac_algo_c_to_s is None:
			return True
		mac = self.conn.recv(self.mac_algo_c_to_s.hash_length)
		return self.mac_algo_c_to_s.verify(data, self._client_sequence_number, mac)
	def generate_mac(self, data):
		if self.mac_algo_s_to_c is None:
			return b""
		return self.mac_algo_s_to_c.generate(data, self._server_sequence_number)
	def decompress(self, data):
		if self.compression_algo_c_to_s is None:
			return data
		return self.compression_algo_c_to_s.decompress(data)
	def compress(self, data):
		if self.compression_algo_s_to_c is None:
			return data
		return self.compression_algo_s_to_c.compress(data)


	def recv(self):
		# Read the first block that should contain the packet length.
		first_block = self.conn.recv(max(8, self.client_block_size))
		if first_block == b"":
			return None # Empty packet
		first_block = self.decrypt(first_block)

		# Packet length is stored in the first four bytes in a uint32
		packet_len = struct.unpack(">I", first_block[:4])[0]

		# Read the remaining packet. Packet length does not include the
		#  actual size of the uint32 storing packet length, so we
		#  accomodate for that by reading 4 less bytes. We have also
		#  already read 4 one block, so accomodate for that too.
		remaining_payload_length = packet_len - self.client_block_size + 4
		remaining_blocks = self.conn.recv(remaining_payload_length)
		remaining_blocks = self.decrypt(remaining_blocks)
		full_packet = first_block + remaining_blocks

		# Read MAC and verify if keys are set
		if not self.verify_mac(full_packet):
			# For now, just do nothing.
			print("FAILED TO VERIFY MAC. TODO: HANDLE")

		# Read the padding and remove it from payload
		padded_compressed_payload = full_packet[4:] # Removing packet length bytes
		padding_length = struct.unpack(">B", padded_compressed_payload[0:1])[0]
		compressed_payload = padded_compressed_payload[1:-padding_length]

		# Handle decompression
		payload = self.decompress(compressed_payload)

		# Increment the client sequence number
		self._client_sequence_number += 1

		# Turn into an SSH msg
		msg = SSH_MSG.read_msg(payload)
		print(f" <- Received {msg.__class__.__name__}")
		return msg


	def send(self, msg):
		print(f" -> Sending {msg.__class__.__name__}")

		# Handle compression
		compressed_payload = self.compress(msg.payload())

		# Calculate the padding
		padding_length = self._calculate_padding_length(compressed_payload)

		# Construct paddinglen || data || padding
		data = (
			struct.pack(">B", padding_length)
			+ compressed_payload
			+ urandom(padding_length))

		# Calculate the packet length (1 + payload size + padding length)
		packet_length = len(data)
		data = (
			struct.pack(">I", packet_length)
			+ data)

		# Generate mac, encrypt data, and generate full packet
		mac = self.generate_mac(data)
		data = self.encrypt(data)
		full_packet = data + mac

		# Increment the server-side sequence number and send
		self._server_sequence_number += 1
		self.conn.send(full_packet)


	def _calculate_padding_length(self, data):
		# The padding should bring the compressed payload + 5 to a
		#  multiple of the block size (+1 for the padding length bytem
		#  and +4 for the uint32 packet_length)
		unpadded_length = len(data) + 1 + 4
		desired_length = math.ceil(unpadded_length / self.server_block_size) * self.server_block_size
		padding_length = desired_length - unpadded_length

		# If the total packet length would be smaller than 16, we need
		#  to increase the packet size via more padding!
		if desired_length < 16:
			nb_blocks_to_pad = (16 - desired_length) // self.server_block_size
			padding_length += nb_blocks_to_pad * self.server_block_size

		# Minimum size of padding is 4, so if otherwise, we need to also
		#  pad more
		if padding_length < 4:
			padding_length += self.server_block_size

		return padding_length
