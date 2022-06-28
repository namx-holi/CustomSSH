import unittest
from data_types import DataReader, DataWriter


class TestReader(unittest.TestCase):

	def test_reading_byte(self):
		data = b"H"
		expected = b"H"

		r = DataReader(data)
		val = r.read_byte()

		self.assertEqual(val, expected)

	def test_reading_bytes(self):
		data = b"Hello World"
		expected = b"Hello"

		r = DataReader(data)
		val = r.read_bytes(5)

		self.assertEqual(val, expected)

	def test_reading_bool_false(self):
		data = b"\x00"
		expected = False

		r = DataReader(data)
		val = r.read_bool()

		self.assertEqual(val, expected)

	def test_reading_bool_true(self):
		data = b"\x01"
		expected = True

		r = DataReader(data)
		val = r.read_bool()

		self.assertEqual(val, expected)

	def test_reading_bool_nonzero(self):
		data = b"\x04"
		expected = True

		r = DataReader(data)
		val = r.read_bool()

		self.assertEqual(val, expected)

	def test_reading_uint8(self):
		data = b"\x42"
		expected = 0x42

		r = DataReader(data)
		val = r.read_uint8()

		self.assertEqual(val, expected)

	def test_reading_uint32(self):
		data = b"\x29\xb7\xf4\xaa"
		expected = 0x29b7f4aa

		r = DataReader(data)
		val = r.read_uint32()

		self.assertEqual(val, expected)

	def test_reading_uint64(self):
		data = b"\x29\xb7\xf4\xaa\x29\xb7\xf4\xaa"
		expected = 0x29b7f4aa29b7f4aa

		r = DataReader(data)
		val = r.read_uint64()

		self.assertEqual(val, expected)

	def test_reading_string(self):
		data = b"\x00\x00\x00\x07testing"
		expected = "testing"

		r = DataReader(data)
		val = r.read_string()

		self.assertEqual(val, expected)

	def test_reading_string_empty(self):
		data = b"\x00\x00\x00\x00"
		expected = ""

		r = DataReader(data)
		val = r.read_string()

		self.assertEqual(val, expected)

	def test_reading_mpint_zero(self):
		data = b"\x00\x00\x00\x00"
		expected = 0

		r = DataReader(data)
		val = r.read_mpint()

		self.assertEqual(val, expected)

	def test_reading_mpint(self):
		data = b"\x00\x00\x00\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7"
		expected = 0x9a378f9b2e332a7

		r = DataReader(data)
		val = r.read_mpint()

		self.assertEqual(val, expected)

	def test_reading_mpint_leading_zero(self):
		data = b"\x00\x00\x00\x02\x00\x80"
		expected = 0x80

		r = DataReader(data)
		val = r.read_mpint()

		self.assertEqual(val, expected)

	def test_reading_mpint_negative(self):
		data = b"\x00\x00\x00\x05\xff\x21\x52\x41\x11"
		expected = -0xdeadbeef

		r = DataReader(data)
		val = r.read_mpint()

		self.assertEqual(val, expected)

	def test_reading_namelist_empty(self):
		data = b"\x00\x00\x00\x00"
		expected = []

		r = DataReader(data)
		val = r.read_namelist()

		self.assertEqual(val, expected)

	def test_reading_namelist_one_item(self):
		data = b"\x00\x00\x00\x04\x7a\x6c\x69\x62"
		expected = ["zlib"]

		r = DataReader(data)
		val = r.read_namelist()

		self.assertEqual(val, expected)

	def test_reading_namelist_two_items(self):
		data = b"\x00\x00\x00\x09\x7a\x6c\x69\x62\x2c\x6e\x6f\x6e\x65"
		expected = ["zlib", "none"]

		r = DataReader(data)
		val = r.read_namelist()

		self.assertEqual(val, expected)


class TestWriter(unittest.TestCase):

	def test_writing_byte(self):
		data = b"H"
		expected = b"H"

		w = DataWriter()
		w.write_byte(data)

		self.assertEqual(w.data, expected)

	def test_writing_bytes(self):
		data = b"Hello"
		expected = b"Hello"

		w = DataWriter()
		w.write_byte(data)

		self.assertEqual(w.data, expected)

	def test_writing_bool_false(self):
		data = False
		expected = b"\x00"

		w = DataWriter()
		w.write_bool(data)

		self.assertEqual(w.data, expected)

	def test_writing_bool_true(self):
		data = True
		expected = b"\x01"

		w = DataWriter()
		w.write_bool(data)

		self.assertEqual(w.data, expected)

	def test_writing_bool_nonzero(self):
		data = 42
		expected = b"\x01"

		w = DataWriter()
		w.write_bool(data)

		self.assertEqual(w.data, expected)

	def test_writing_uint8(self):
		data = 0x42
		expected = b"\x42"

		w = DataWriter()
		w.write_uint8(data)

		self.assertEqual(w.data, expected)

	def test_writing_uint32(self):
		data = 0x29b7f4aa
		expected = b"\x29\xb7\xf4\xaa"

		w = DataWriter()
		w.write_uint32(data)

		self.assertEqual(w.data, expected)

	def test_writing_uint64(self):
		data = 0x29b7f4aa29b7f4aa
		expected = b"\x29\xb7\xf4\xaa\x29\xb7\xf4\xaa"

		w = DataWriter()
		w.write_uint64(data)

		self.assertEqual(w.data, expected)

	def test_writing_string(self):
		data = "testing"
		expected = b"\x00\x00\x00\x07testing"

		w = DataWriter()
		w.write_string(data)

		self.assertEqual(w.data, expected)

	def test_writing_string_empty(self):
		data = ""
		expected = b"\x00\x00\x00\x00"

		w = DataWriter()
		w.write_string(data)

		self.assertEqual(w.data, expected)

	def test_writing_string_bytes(self):
		data = b"testing"
		expected = b"\x00\x00\x00\x07testing"

		w = DataWriter()
		w.write_string(data)

		self.assertEqual(w.data, expected)

	def test_writing_mpint_zero(self):
		data = 0
		expected = b"\x00\x00\x00\x00"

		w = DataWriter()
		w.write_mpint(data)

		self.assertEqual(w.data, expected)

	def test_writing_mpint(self):
		data = 0x9a378f9b2e332a7
		expected = b"\x00\x00\x00\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7"

		w = DataWriter()
		w.write_mpint(data)

		self.assertEqual(w.data, expected)

	def test_writing_mpint_leading_zero(self):
		data = 0x80
		expected = b"\x00\x00\x00\x02\x00\x80"

		w = DataWriter()
		w.write_mpint(data)

		self.assertEqual(w.data, expected)

	def test_writing_mpting_negative(self):
		data = -0xdeadbeef
		expected = b"\x00\x00\x00\x05\xff\x21\x52\x41\x11"

		w = DataWriter()
		w.write_mpint(data)

		self.assertEqual(w.data, expected)

	def test_writing_namelist_empty(self):
		data = []
		expected = b"\x00\x00\x00\x00"

		w = DataWriter()
		w.write_namelist(data)

		self.assertEqual(w.data, expected)

	def test_writing_namelist_one_item(self):
		data = ["zlib"]
		expected = b"\x00\x00\x00\x04\x7a\x6c\x69\x62"

		w = DataWriter()
		w.write_namelist(data)

		self.assertEqual(w.data, expected)

	def test_writing_namelist_two_items(self):
		data = ["zlib", "none"]
		expected = b"\x00\x00\x00\x09\x7a\x6c\x69\x62\x2c\x6e\x6f\x6e\x65"

		w = DataWriter()
		w.write_namelist(data)

		self.assertEqual(w.data, expected)
