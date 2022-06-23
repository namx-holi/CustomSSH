"""
Handles reading and writing of data types

byte
	A byte represents an arbitrary 8-bit value (octet). Fixed length
	data is sometimes represented as an array of bytes, written byte[n],
	where n is the number of bytes in the array.

boolean
	A boolean value is stored as a single byte. The value 0 represents
	FALSE, and the value 1 represents TRUE. All non-zero values MUST
	be interpreted as TRUE; however, applications MUST NOT store values
	other than 0 and 1.

uint32
	Represents a 32-bit unsigned integer. Stored as four bytes in the
	order of decreasing significance (network byte order). For example:
	the value 0x29b7f4aa is stored as 29 b7 f4 aa.

uint64
	Represents a 64-bit unsigned integer. Stored as eight bytes in the
	order of decreasing significance (network byte order).

string
	Arbitrary length binary string. Strings are allowed to contain
	arbitrary binary data, including null characters and 8-bit
	characters. They are stored as uint32 containing its length
	(number of bytes that follow) and zero (= empty string) or more
	bytes that are the value of the string. Terminating null
	characters are not used.

	Strings are also used to store text. In that case, US-ASCII is
	used for internal names, and ISO-10646 UTF-8 for text that might
	be displayed to the user. The terminating null character SHOULD NOT
	normally be stored in the string. For example: the US-ASCII string
	"testing" is represented as 00 00 00 07 t e s t i n g. The UTF-8
	mapping does not alter the encoding of US-ASCII characters.

mpint
	Represents multiple precision integers in two's complement format,
	stored as a string, 8 bits per byte, MSB first. Negative numbers
	have the value 1 as the most significant bit of the first byte of
	the data partition. If the most significant bit would be set for a
	positive number, the number MUST be preceded by a zero byte.
	Unnecessary leading bytes with the value 0 or 255 MUST NOT be
	included. The value zero MUST be stored as a string with zero
	bytes of data.

	By convention, a number that is used in modular computations in Z_n
	SHOULD be represented in the range 0 <= x < n.

	Examples:
	value (hex)        representation (hex)
	-----------        --------------------
	0                  00 00 00 00
	9a378f9b2e332a7    00 00 00 08 09 a3 78 f9 b2 e3 32 a7
	80                 00 00 00 02 00 80
	-1234              00 00 00 02 ed cc
	-deadbeef          00 00 00 05 ff 21 52 41 11

name-list
	A string containing a comma-separated list of names. A name-list is
	represented as a uint32 containing its length (number of bytes that
	follow) followed by a comma-separated list of zero or more names. A
	name MUST have a non-zero length, and it MUST NOT contain a comma
	(","). As this is a list of names, all of the elements contained are
	names and MUST be in US-ASCII. Contet may impose additional
	restrictions on the names. For example, the names in a name-list may
	have to be a list of valid algorithm identifiers, or a list of
	[RFC3066] language tags. The order of the names in a name-list may
	or may not be significant. Again, this depends on the context in
	which the list is used. Terminating null characters MUST NOT be
	used, neither for the individual names, nor for the list as a whole.

	Examples:
	value                      representation (hex)
	-----                      --------------------
	(), the empty name-list    00 00 00 00
	("zlib")                   00 00 00 04 7a 6c 69 62
	("zlib,none")              00 00 00 09 7a 6c 69 62 2c 6e 6f 6e 65
"""


import struct



class DataReader:
	def __init__(self, data):
		self.data = data
		self.head = 0 # What byte we are up to reading

	def read_byte(self):
		return self.read_bytes(1)

	def read_bytes(self, n):
		b = self.data[self.head:self.head+n]
		self.head += n
		return b

	def read_bool(self):
		b = self.read_bytes(1)
		return struct.unpack(">?", b)[0]

	def read_uint8(self):
		b = self.read_bytes(1)
		return struct.unpack(">B", b)[0]

	def read_uint32(self):
		b = self.read_bytes(4)
		return struct.unpack(">I", b)[0]

	def read_uint64(self):
		b = self.read_bytes(8)
		return struct.unpack(">Q", b)[0]

	def read_string(self, us_ascii=True):
		str_len = self.read_uint32()
		str_bytes = self.read_bytes(str_len)

		# US-ASCII for internal names, otherwise UTF-8
		if us_ascii:
			return str_bytes.decode()
		return str_bytes.decode("utf-8")

	def read_mpint(self):
		mpint_len = self.read_uint32()

		# zero is represented with an empty string
		if mpint_len == 0:
			return 0

		num_bytes = self.read_bytes(mpint_len)
		return int.from_bytes(num_bytes, "big", signed=True)

	# def read_fixed_length_int(self, size):
	# 	num_bytes = self.read_bytes(size)
	# 	return int.from_bytes(num_bytes, "big", signed=True)

	def read_namelist(self):
		namelist_len = self.read_uint32()
		if namelist_len == 0:
			return []

		namelist_bytes = self.read_bytes(namelist_len)

		namelist_str = namelist_bytes.decode() # US-ASCII
		return namelist_str.split(",")


class DataWriter:
	def __init__(self):
		self.data = b""

	def write_byte(self, data):
		self.write_bytes(data)

	def write_bytes(self, data):
		self.data += data

	def write_bool(self, val):
		b = struct.pack(">?", val)
		self.write_bytes(b)

	def write_uint8(self, num):
		b = struct.pack(">B", num)
		self.write_bytes(b)

	def write_uint32(self, num):
		b = struct.pack(">I", num)
		self.write_bytes(b)

	def write_uint64(self, num):
		b = struct.pack(">Q", num)
		self.write_bytes(b)

	def write_string(self, data, us_ascii=True):
		# If the data is not already encoded, we need to encode
		if isinstance(data, str):
			if us_ascii:
				str_bytes = data.encode() # US-ASCII
			else:
				str_bytes = data.encode("utf-8")
		else:
			str_bytes = data

		str_len = len(str_bytes)
		self.write_uint32(str_len)
		self.write_bytes(str_bytes)

	def write_mpint(self, num):
		# zero is represented with an empty string
		if num == 0:
			self.write_uint32(0)
			return

		# TODO: Write something about this line
		mpint_len = (~num if num < 0 else num).bit_length() // 8 + 1

		mpint_bytes = num.to_bytes(mpint_len, "big", signed=True)
		self.write_uint32(mpint_len)
		self.write_bytes(mpint_bytes)

	def write_namelist(self, names):
		namelist_str = ",".join(names)
		namelist_bytes = namelist_str.encode() # US-ASCII
		namelist_len = len(namelist_bytes)
		self.write_uint32(namelist_len)
		self.write_bytes(namelist_bytes)
