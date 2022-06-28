import unittest
from algorithms import NoCompression, LZ77


class TestLZ77(unittest.TestCase):
	
	def test_compress(self):
		data = b'\x05\x00\x00\x00\x0cssh-userauth'
		expected = b'x\x9cbe``\xe0).\xce\xd0--N-J,-\xc9\x00\x08'

		algo = LZ77()
		algo.initialise()
		val = algo.compress(data)

		self.assertEqual(val, expected)

	def test_decompress(self):
		data = b'x\x9cbe``\xe0).\xce\xd0--N-J,-\xc9\x00\x08'
		expected = b'\x05\x00\x00\x00\x0cssh-userauth'

		algo = LZ77()
		algo.initialise()
		val = algo.decompress(data)

		self.assertEqual(val, expected)


class TestNoCompression(unittest.TestCase):

	def test_compress(self):
		data = b'\x05\x00\x00\x00\x0cssh-userauth'
		expected = b'\x05\x00\x00\x00\x0cssh-userauth'

		algo = NoCompression()
		algo.initialise()
		val = algo.compress(data)

		self.assertEqual(val, expected)

	def test_decompress(self):
		data = b'\x05\x00\x00\x00\x0cssh-userauth'
		expected = b'\x05\x00\x00\x00\x0cssh-userauth'

		algo = NoCompression()
		algo.initialise()
		val = algo.decompress(data)

		self.assertEqual(val, expected)