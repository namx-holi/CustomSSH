
import math
import struct
from messages import SSH_MSG
from os import urandom


class PacketHandler:
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


	def read_message(self):
		# TODO: Handle encryption
		# TODO: Handle compression
		# TODO: Handle MAC

		# For now, assume block size is 8
		block_size = 8

		# Decrypt the length after receiving the first 8 or cipher
		#  block size of packet
		first_block = self.conn.recv(max(8, block_size))
		packet_len = struct.unpack(">I", first_block[:4])[0]

		# Read the remaining packet. We over-read with the first block,
		#  so we need to accomodate for this.
		remaining_payload_length = packet_len - (block_size - 4)
		padded_compressed_payload = first_block[4:] + self.conn.recv(remaining_payload_length)

		# TODO: Read MAC and verify
		...

		# Read the padding and remove it from payload
		padding_length = struct.unpack(">B", padded_compressed_payload[0:1])[0]
		compressed_payload = padded_compressed_payload[1:-padding_length]

		# TODO: Handle decompression
		payload = compressed_payload

		# Increment the client sequence number
		self._client_sequence_number += 1

		# Turn into an SSH msg
		return SSH_MSG.read_msg(payload)


	def send_message(self, msg):
		# TODO: Handle encryption
		# TODO: Handle compression
		# TODO: Handle MAC

		# For now, assume block size is 8
		block_size = 8

		# TODO: Handle compression
		compressed_payload = msg.payload()

		# Calculate the padding
		# padding_length = 4
		unpadded_length = len(compressed_payload) + 1 + 4
		# The padding should bring the compresed payload + 5 to a
		#  multiple of the block size (+1 for the padding length byte,
		#  and +4 for the packet length)
		desired_length = math.ceil(unpadded_length/block_size) * block_size
		padding_length = desired_length - unpadded_length
		# If the total packet length would be smaller than 16, we need
		#  to bring it higher
		if desired_length < 16:
			nb_blocks_to_pad = (16 - desired_length)//block_size
			padding_length += block_size * nb_blocks_to_pad
		# If the padding is smaller than 4, we need to bring it higher
		if padding_length < 4:
			padding_length += block_size

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

		# Calculate MAC
		mac = b""
		...

		# Encrypt the data and add mac
		# TODO
		data = data + mac

		# Increment the server-side sequence number and send
		self._server_sequence_number += 1
		self.conn.send(data)
