
from apps.doom.helpers import *
from apps.doom.map import Map

class WAD:
	
	def __init__(self, filename):
		self.filename = filename

		# Set when reading the file content
		self.raw_data = None

		# Set when reading headers
		self.wad_type = None
		self.directory_count = None
		self.directory_offset = None

		# Set when reading directories
		self.directories = []


	def load(self):
		self.load_file()
		self.load_header()
		self.load_directories()


	def load_file(self):
		# Reads all content from the given file
		with open(self.filename, "rb") as stream:
			self.raw_data = stream.read()


	def load_header(self):
		# Read the wad type, directory count, and directory offset
		self.wad_type         = self.raw_data[0:4].decode()
		self.directory_count  = read_uint32(self.raw_data, 4)
		self.directory_offset = read_uint32(self.raw_data, 8)


	def load_directories(self):
		for i in range(self.directory_count):
			# i*16 added to directory offset as each directory takes up
			#  16 bytes
			offset      = self.directory_offset + i*16
			lump_offset = read_uint32(self.raw_data, offset)
			lump_size   = read_uint32(self.raw_data, offset+4)
			lump_name   = self.raw_data[offset+8:offset+16].rstrip(b"\x00").decode()

			# Add directory to list
			self.directories.append(dict(lump_offset=lump_offset, lump_size=lump_size, lump_name=lump_name))


	def get_lump(self, directory):
		offset = directory["lump_offset"]
		size = directory["lump_size"]
		return self.raw_data[offset:offset+size]


	def load_map(self, map_name, players):
		# Search through directories until we reach the map name
		try:
			directory_index = [d["lump_name"] for d in self.directories].index(map_name)
		except ValueError:
			# Map not found
			return None

		m = Map(map_name, players)

		# Load things for the map
		m.load_things  (self.get_lump(self.directories[directory_index + 1]))
		m.load_linedefs(self.get_lump(self.directories[directory_index + 2]))
		m.load_sidedefs(self.get_lump(self.directories[directory_index + 3]))
		m.load_vertexes(self.get_lump(self.directories[directory_index + 4]))
		m.load_segs    (self.get_lump(self.directories[directory_index + 5]))
		m.load_ssectors(self.get_lump(self.directories[directory_index + 6]))
		m.load_nodes   (self.get_lump(self.directories[directory_index + 7]))
		m.load_sectors (self.get_lump(self.directories[directory_index + 8]))
		m.load_reject  (self.get_lump(self.directories[directory_index + 9]))
		m.load_blockmap(self.get_lump(self.directories[directory_index + 10]))
		return m
