import struct


# Helper methods to read numbers etc
def read_int16(data, offset):
	b = data[offset:offset+2]
	return struct.unpack("h", b)[0]
def read_uint16(data, offset):
	b = data[offset:offset+2]
	return struct.unpack("H", b)[0]
def read_int32(data, offset):
	b = data[offset:offset+4]
	return struct.unpack("i", b)[0]
def read_uint32(data, offset):
	b = data[offset:offset+4]
	return struct.unpack("I", b)[0]


def normalise_angle(a):
	"""
	Adjusts an angle to be within the range [0, 360]
	"""
	return a % 360
