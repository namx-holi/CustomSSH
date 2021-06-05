import struct


class ReadHelper:
	def __init__(self, data):
		self.data = data
		self.head = 0

	@property
	def remaining(self):
		return len(self.data) - self.head

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
		...

	def read_string(self, ascii=False):
		"""
		Arbitrary length binary string.  Strings are allowed to contain
		arbitrary binary data, including null characters and 8-bit
		characters.  They are stored as a uint32 containing its length
		(number of bytes that follow) and zero (=empty string) or more
		bytes that are the value of the string.  Terminating null
		characters are not used.

		Strings are also used to store text.  In that case, US-ASCII is
		used for internal names, and ISO-10646 UTF-8 for text that might
		be displayed to the user.  The terminating null character SHOULD
		NOT normally be stored in the string.  For example: the US-ASCII
		string "testing" is represented as 00 00 00 07 t e s t i n g.  The
		UTF-8 mapping does not alter the encoding of US-ASCII characters.
		"""
		str_len = self.read_uint32()
		str_b = self.read_bytes(str_len)

		if ascii:
			return str_b.decode("utf-8")
		return str_b

	def read_mpint(self):
		"""
		Represents multiple precision integers in two's complement format,
		stored as a string, 8 bits per byte, MSB first.  Negative numbers
		have the value 1 as the most significant bit of the first byte of
		the data partition.  If the most significant bit would be set for
		a positive number, the number MUST be preceded by a zero byte.
		Unnecessary leading bytes with the value 0 or 255 MUST NOT be
		included.  The value zero MUST be stored as a string with zero
		bytes of data.

		By convention, a number that is used in modular computations in
		Z_n SHOULD be represented in the range 0 <= x < n.

			Examples:

			value (hex)			representation (hex)
			-----------			--------------------
			0					00 00 00 00
			9a378f9b2e332a7		00 00 00 08 09 a3 78 f9 b2 e3 32 a7
			80					00 00 00 02 00 80
			-1234				00 00 00 02 ed cc
			-deadbeef			00 00 00 05 ff 21 52 41 11
		"""
		mpint_len = self.read_uint32()
		if mpint_len == 0:
			# Special case where 0 is zero length string
			return 0

		num_b = self.read_bytes(mpint_len)
		return int.from_bytes(num_b, "big", signed=True)

	def read_namelist(self):
		"""
		A string containing a comma-separated list of names.  A name-list
		is represented as a uint32 containing its length (number of bytes
		that follow) followed by a comma-separated list of zero or more
		names.  A name MUST haev a non-zero length, and it MUST NOT
		contain a comma (",").  As this is a list of names, all of the
		elements contained are names and MUST be in US-ASCII.  Context may
		impose additional restrictions on the names.  For example, the
		names in a name-list may have to be a list of valid algorithm
		identifiers (see Section 6 below), or a list of [RFC3066] language
		tags.  The order of the names in a name-list may or may not be
		significatn.  Again, this depends on the context in which the list
		is used.  Terminating null characters MUST NOT be used, neither
		for the individual names, oor for the list as a whole.

			Examples:

			value						representation (hex)
			-----						--------------------
			(), the empty name-list		00 00 00 00
			("zlib")					00 00 00 04 7a 6c 69 62
			("zlib,none")				00 00 00 09 7a 6c 69 62 2c 6e 6f 6e 65
		"""
		size = self.read_uint32()
		namelist_b = self.read_bytes(size)

		namelist = namelist_b.decode()
		names = namelist.split(",")
		return names



class WriteHelper:
	def __init__(self):
		self.data = b""

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
		...

	def write_string(self, data):
		"""
		Arbitrary length binary string.  Strings are allowed to contain
		arbitrary binary data, including null characters and 8-bit
		characters.  They are stored as a uint32 containing its length
		(number of bytes that follow) and zero (=empty string) or more
		bytes that are the value of the string.  Terminating null
		characters are not used.

		Strings are also used to store text.  In that case, US-ASCII is
		used for internal names, and ISO-10646 UTF-8 for text that might
		be displayed to the user.  The terminating null character SHOULD
		NOT normally be stored in the string.  For example: the US-ASCII
		string "testing" is represented as 00 00 00 07 t e s t i n g.  The
		UTF-8 mapping does not alter the encoding of US-ASCII characters.
		"""
		if isinstance(data, str):
			str_b = data.encode("utf-8")
		else:
			str_b = data

		str_len = len(str_b)
		self.write_uint32(str_len)
		self.write_bytes(str_b)

	def write_mpint(self, num):
		"""
		Represents multiple precision integers in two's complement format,
		stored as a string, 8 bits per byte, MSB first.  Negative numbers
		have the value 1 as the most significant bit of the first byte of
		the data partition.  If the most significant bit would be set for
		a positive number, the number MUST be preceded by a zero byte.
		Unnecessary leading bytes with the value 0 or 255 MUST NOT be
		included.  The value zero MUST be stored as a string with zero
		bytes of data.

		By convention, a number that is used in modular computations in
		Z_n SHOULD be represented in the range 0 <= x < n.

			Examples:

			value (hex)			representation (hex)
			-----------			--------------------
			0					00 00 00 00
			9a378f9b2e332a7		00 00 00 08 09 a3 78 f9 b2 e3 32 a7
			80					00 00 00 02 00 80
			-1234				00 00 00 02 ed cc
			-deadbeef			00 00 00 05 ff 21 52 41 11
		"""
		if num == 0:
			# Special case where 0 is zero length string
			self.write_uint32(0)
			return

		mpint_len = (~num if num < 0 else num).bit_length() // 8 + 1
		num_b = num.to_bytes(mpint_len, "big", signed=True)
		self.write_uint32(mpint_len)
		self.write_bytes(num_b)

	def write_namelist(self, names):
		"""
		A string containing a comma-separated list of names.  A name-list
		is represented as a uint32 containing its length (number of bytes
		that follow) followed by a comma-separated list of zero or more
		names.  A name MUST haev a non-zero length, and it MUST NOT
		contain a comma (",").  As this is a list of names, all of the
		elements contained are names and MUST be in US-ASCII.  Context may
		impose additional restrictions on the names.  For example, the
		names in a name-list may have to be a list of valid algorithm
		identifiers (see Section 6 below), or a list of [RFC3066] language
		tags.  The order of the names in a name-list may or may not be
		significatn.  Again, this depends on the context in which the list
		is used.  Terminating null characters MUST NOT be used, neither
		for the individual names, oor for the list as a whole.

			Examples:

			value						representation (hex)
			-----						--------------------
			(), the empty name-list		00 00 00 00
			("zlib")					00 00 00 04 7a 6c 69 62
			("zlib,none")				00 00 00 09 7a 6c 69 62 2c 6e 6f 6e 65
		"""
		namelist = ",".join(names)
		namelist_b = namelist.encode("utf-8")
		self.write_uint32(len(namelist_b))
		self.write_bytes(namelist_b)



class GenericHandler:
	@property
	def available_algorithms(self):
		alg_and_prio = [
			(a, self.algorithms[a]["priority"])
			for a in self.algorithms
			if self.algorithms[a]["available"]]

		alg_and_prio.sort(key=lambda x:x[1], reverse=True)
		return [a for a,p in alg_and_prio]
