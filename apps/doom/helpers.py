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


# Helper for Binary Angular Measurement
class Angle:
	def __init__(self, angle=0):
		self.angle = self._normalise_angle(angle)

	@staticmethod
	def _normalise_angle(angle):
		# return int(angle % 360)
		return angle % 360

	# Comparison
	def __lt__(self, other): # a < b
		return self.angle < other
	def __le__(self, other): # a <= b
		return self.angle <= other
	def __eq__(self, other): # a == b
		return self.angle == other
	def __ne__(self, other): # a != b
		return self.angle != other
	def __gt__(self, other): # a > b
		return self.angle > other
	def __ge__(self, other): # a >= b
		return self.angle >= other

	# Basic arithmetic
	def __add__(self, other): # a + b
		if isinstance(other, Angle): return Angle(self.angle + other.angle)
		else: return Angle(self.angle + other)
	def __sub__(self, other): # a - b
		if isinstance(other, Angle): return Angle(self.angle - other.angle)
		else: return Angle(self.angle - other)
	def __mul__(self, other): # a * b
		return Angle(self.angle * other)
	def __truediv__(self, other): # a / b
		return Angle(self.angle / other)
	def __neg__(self): # -a
		return Angle(-self.angle)
	def __pos__(self): # +a
		return Angle(self.angle)


	# augmented arithmetic assignments (+= or -=)
	def __iadd__(self, other):
		if isinstance(other, Angle): return Angle(self.angle + other.angle)
		else: return Angle(self.angle + other)
	def __isub__(self, other):
		if isinstance(other, Angle): return Angle(self.angle - other.angle)
		else: return Angle(self.angle - other)

	def __repr__(self):
		return f"<Angle {self.angle}>"
