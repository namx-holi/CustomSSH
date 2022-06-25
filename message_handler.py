
import math
import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from os import urandom

from data_types import DataWriter
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
		self.client_block_size = 8 
		self.server_block_size = 8

		# Encryption and integrity keys expected lengths in bytes
		self.initial_iv_client_len     = 16 # aes128-cbc
		self.initial_iv_server_len     = 16 # aes128-cbc
		self.encryption_key_client_len = 16 # aes128-cbc
		self.encryption_key_server_len = 16 # aes128-cbc
		self.integrity_key_client_len  = 20 # hmac-sha1
		self.integrity_key_server_len  = 20 # hmac-sha1

		# Sizes of MACs
		self.integrity_hash_client_len = 20 # hmac-sha1
		self.integrity_hash_server_len = 20 # hmac-sha1

		# Encryption and integrity keys
		self.initial_iv_client     = None
		self.initial_iv_server     = None
		self.encryption_key_client = None
		self.encryption_key_server = None
		self.integrity_key_client  = None
		self.integrity_key_server  = None

		# Instances of ciphers are stored after initialised
		self.encryption_cipher_client = None
		self.encryption_cipher_server = None

		self.encryption_enabled = False
		self.mac_enabled = False


	def recv(self):
		# TODO: Compression

		# Read the first block that should contain the packet length.
		first_block = self.conn.recv(max(8, self.client_block_size))
		if first_block == b"":
			return None # Empty packet

		# If encryption keys are set, then we need to decrypt this block
		if self.encryption_enabled:
			first_block = self.decrypt(first_block)

		# Packet length is stored in the first four bytes in a uint32
		packet_len = struct.unpack(">I", first_block[:4])[0]

		# Read the remaining packet. Packet length does not include the
		#  actual size of the uint32 storing packet length, so we
		#  accomodate for that by reading 4 less bytes. We have also
		#  already read 4 one block, so accomodate for that too.
		remaining_payload_length = packet_len - self.client_block_size + 4
		remaining_blocks = self.conn.recv(remaining_payload_length)
		# If encryption keys are set, then we need to decrypt these blocks
		if self.encryption_enabled:
			remaining_blocks = self.decrypt(remaining_blocks)
		full_packet = first_block + remaining_blocks

		# Read MAC and verify if keys are set
		if self.mac_enabled:
			mac = self.conn.recv(self.integrity_hash_client_len)
			if not self.verify_mac(first_block + remaining_blocks, mac):
				# For now, just do nothing.
				print("FAILED TO VERIFY MAC")

		# Read the padding and remove it from payload
		padded_compressed_payload = full_packet[4:] # Removing packet length bytes
		padding_length = struct.unpack(">B", padded_compressed_payload[0:1])[0]
		compressed_payload = padded_compressed_payload[1:-padding_length]

		# TODO: Handle decompression
		payload = compressed_payload

		# Increment the client sequence number
		self._client_sequence_number += 1

		# Turn into an SSH msg
		msg = SSH_MSG.read_msg(payload)
		print(f" <- Received {msg.__class__.__name__}")
		return msg


	def send(self, msg):
		# TODO: Compression
		print(f" -> Sending {msg.__class__.__name__}")

		# TODO: Handle compression
		compressed_payload = msg.payload()

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

		# If keys are set, we need to generate mac
		if self.mac_enabled:
			mac = self.generate_mac(data)
		else:
			mac = b""

		# If keys are set, we need to encrypt
		if self.encryption_enabled:
			data = self.encrypt(data)

		# Add on the mac
		data += mac

		# Increment the server-side sequence number and send
		self._server_sequence_number += 1
		self.conn.send(data)


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


	def setup_keys(self, HASH, K, H, session_id):
		# K is a large number. It needs to be an mpint however
		w = DataWriter()
		w.write_mpint(K)
		K = w.data

		# Method to reduce duplicate code to handle generating a key
		#  with the correct length
		def _generate_key(X, length): # SSH-TRANS 7.2.
			# HASH(K || H || X || session_id)
			key = HASH(K + H + X + session_id).digest()
			# If the key length needed is longer than the output of HASH,
			#  the key is extended by computing HASH of the concattenation
			#  of K and H and the entire key so far, and apppending the
			#  resulting bytes to the key. This process is repeated until
			#  enough key material is available.
			while len(key) < length:
				key += HASH(K + H + key).digest()

			# Key data MUST be taken from the beginning of the hash output.
			return key[:length]

		self.initial_iv_client     = _generate_key(b"A", self.initial_iv_client_len)
		self.initial_iv_server     = _generate_key(b"B", self.initial_iv_server_len)
		self.encryption_key_client = _generate_key(b"C", self.encryption_key_client_len)
		self.encryption_key_server = _generate_key(b"D", self.encryption_key_server_len)
		self.integrity_key_client  = _generate_key(b"E", self.integrity_key_client_len)
		self.integrity_key_server  = _generate_key(b"F", self.integrity_key_server_len)


	def enable_encryption(self):
		self.client_block_size = self.initial_iv_client_len
		self.server_block_size = self.initial_iv_server_len
		self.encryption_enabled = True

	def enable_integrity(self):
		self.mac_enabled = True


	def encrypt(self, data): # aes128-cbc
		# If not initialised, we need to init with our iv
		if self.encryption_cipher_server is None:
			self.encryption_cipher_server = AES.new(
				self.encryption_key_server,
				AES.MODE_CBC,
				self.initial_iv_server)
		# Return encrypted data
		return self.encryption_cipher_server.encrypt(data)


	def decrypt(self, data): # aes128-cbc
		# If not initialised, we need to init with clients iv
		if self.encryption_cipher_client is None:
			self.encryption_cipher_client = AES.new(
				self.encryption_key_client,
				AES.MODE_CBC,
				self.initial_iv_client)
		# Return decrypted data
		return self.encryption_cipher_client.decrypt(data)


	def generate_mac(self, data): # hmac-sha1
		sequence_number_b = struct.pack(">I", self._server_sequence_number)
		h = HMAC.new(self.integrity_key_server, digestmod=SHA1)
		h.update(sequence_number_b + data)
		return h.digest()


	def verify_mac(self, data, mac): # hmac-sha1
		sequence_number_b = struct.pack(">I", self._client_sequence_number)
		h = HMAC.new(self.integrity_key_client, digestmod=SHA1)
		h .update(sequence_number_b + data)
		return h.digest() == mac
