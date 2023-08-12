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
	Adjusts an angle to be within the range [-180, 180]
	"""
	return (a + 180) % 360 - 180


# Class that can be used to perform some vector methods
class Vector:

	def __init__(self, x, y):
		self.x = x
		self.y = y

	def cross(self, v):
		# Cross product
		return self.x * v.y - self.y * v.x

	def __add__(self, v):
		return Vector(self.x + v.x, self.y + v.y)

	def __sub__(self, v):
		return Vector(self.x - v.x, self.y - v.y)

	def __mul__(self, other):
		return Vector(self.x * other, self.y * other)

	def __repr__(self):
		return f"<Vector ({self.x}, {self.y})>"
