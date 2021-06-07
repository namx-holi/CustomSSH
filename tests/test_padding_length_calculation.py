import math


# Sets of numbers to test with.
# (Overall length, Packet length, Padding length, Data length)
test_sets = [
	(1592, 1588,  6, 1581),
	(1080, 1076,  6, 1069),
	(  24,   20,  6,   13),
	( 280,  276,  8,  267),
	( 272,  268,  6,  261),
	( 832,  828,  8,  819),
	(  16,   12, 10,    1),
]


block_size = 8


def test():
	# Test all the sets
	for overall_len, packet_len, padding_len, data_len in test_sets:
		
		assert overall_len == packet_len + 4
		assert (overall_len % 8) == 0

		assert (data_len + padding_len + 1) == packet_len



		# We need to try predict the padding size.
		unpadded_length = data_len + 1 # EG: = 2

		# EG: We want to padd this to 12 by padding with 10.
		desired_overall_len = max(
			16,
			math.ceil(unpadded_length/block_size) * block_size)
		desired_packet_len = desired_overall_len - 4

		calculated_padding_len = desired_packet_len - unpadded_length
		if calculated_padding_len < 4:
			calculated_padding_len += block_size

		# Check if we did a good job...?
		assert calculated_padding_len == padding_len
