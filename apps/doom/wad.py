
import struct


# Helper methods to read numbers etc
def _read_int16(data, offset):
	b = data[offset:offset+2]
	return struct.unpack("h", b)[0]
def _read_uint16(data, offset):
	b = data[offset:offset+2]
	return struct.unpack("H", b)[0]
def _read_int32(data, offset):
	b = data[offset:offset+4]
	return struct.unpack("i", b)[0]
def _read_uint32(data, offset):
	b = data[offset:offset+4]
	return struct.unpack("I", b)[0]



class Map:
	def __init__(self, name):
		self.name = name

		self.linedefs = []
		self.vertexes = []


	def load_things(self, data):
		...

	def load_linedefs(self, data):
		# Each linedef is 14 bytes
		for i in range(0, len(data), 14):
			linedef = Map_Linedef(
				start_vertex  = _read_uint16(data, i),
				end_vertex    = _read_uint16(data, i+2),
				flags         = _read_uint16(data, i+4),
				line_type     = _read_uint16(data, i+6),
				sector_tag    = _read_uint16(data, i+8),
				right_sidedef = _read_uint16(data, i+10),
				left_sidedef  = _read_uint16(data, i+12))
			self.linedefs.append(linedef)

	def load_sidedefs(self, data):
		...

	def load_vertexes(self, data):
		# Each vertex is 4 bytes
		for i in range(0, len(data), 4):
			vertex = Map_Vertex(
				x = _read_int16(data, i),
				y = _read_int16(data, i+2))
			self.vertexes.append(vertex)

	def load_segs(self, data):
		...

	def load_ssectors(self, data):
		...

	def load_nodes(self, data):
		...

	def load_sectors(self, data):
		...

	def load_reject(self, data):
		...

	def load_blockmap(self, data):
		...

	def __repr__(self):
		return (
			f"<Map {self.name}: "
			+ f"0 things, "
			+ f"{len(self.linedefs)} linedefs, "
			+ f"0 sidedefs, "
			+ f"{len(self.vertexes)} vertexes, "
			+ f"0 segs, "
			+ f"0 ssectors, "
			+ f"0 nodes, "
			+ f"0 sectors, "
			+ f"0 reject, "
			+ f"0 blockmap>")



class Map_Linedef:
	def __init__(self, start_vertex, end_vertex, flags, line_type, sector_tag, right_sidedef, left_sidedef):
		self.start_vertex = start_vertex
		self.end_vertex = end_vertex
		self.flags = flags
		self.line_type = line_type
		self.sector_tag = sector_tag
		self.right_sidedef = right_sidedef
		self.left_sidedef = left_sidedef
class Map_Vertex:
	def __init__(self, x, y):
		self.x = x
		self.y = y


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
		self.wad_type = self.raw_data[0:4].decode()
		self.directory_count = _read_uint32(self.raw_data, 4)
		self.directory_offset = _read_uint32(self.raw_data, 8)


	def load_directories(self):
		for i in range(self.directory_count):
			# i*16 added to directory offset as each directory takes up
			#  16 bytes
			offset = self.directory_offset + i*16
			lump_offset = _read_uint32(self.raw_data, offset)
			lump_size = _read_uint32(self.raw_data, offset+4)
			lump_name = self.raw_data[offset+8:offset+16].rstrip(b"\x00").decode()

			# Add directory to list
			self.directories.append(dict(lump_offset=lump_offset, lump_size=lump_size, lump_name=lump_name))


	def get_lump(self, directory):
		offset = directory["lump_offset"]
		size = directory["lump_size"]
		return self.raw_data[offset:offset+size]


	def load_map(self, map_name):
		# Search through directories until we reach the map name
		try:
			directory_index = [d["lump_name"] for d in self.directories].index(map_name)
		except ValueError:
			# Map not found
			return None

		m = Map(map_name)

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
