
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

		# All the things loaded from WAD
		self.things = []
		self.linedefs = []
		self.sidedefs = []
		self.vertexes = []
		self.segs = []
		self.subsectors = []
		self.nodes = []
		self.sectors = []
		self.reject = None
		self.blockmap = None


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

		# Load all objects in the map. We can just increase directory
		#  index as the order of these directories is and must always be
		#  the same.
		self.load_things    (self.get_lump(self.directories[directory_index + 1]))
		self.load_linedefs  (self.get_lump(self.directories[directory_index + 2]))
		self.load_sidedefs  (self.get_lump(self.directories[directory_index + 3]))
		self.load_vertexes  (self.get_lump(self.directories[directory_index + 4]))
		self.load_segs      (self.get_lump(self.directories[directory_index + 5]))
		self.load_subsectors(self.get_lump(self.directories[directory_index + 6]))
		self.load_nodes     (self.get_lump(self.directories[directory_index + 7]))
		self.load_sectors   (self.get_lump(self.directories[directory_index + 8]))
		self.load_reject    (self.get_lump(self.directories[directory_index + 9]))
		self.load_blockmap  (self.get_lump(self.directories[directory_index + 10]))

		# Create the map object from the WAD
		m = Map(self, map_name, players)
		return m


	def load_things(self, data):
		# Each thing is 10 bytes
		for i in range(0, len(data), 10):
			thing = WAD_Thing(
				x     = read_int16(data, i),
				y     = read_int16(data, i+2),
				angle = read_uint16(data, i+4),
				type_ = read_uint16(data, i+6),
				flags = read_uint16(data, i+8))
			self.things.append(thing)

	def load_linedefs(self, data):
		# Each linedef is 14 bytes
		for i in range(0, len(data), 14):
			linedef = WAD_Linedef(
				start_vertex  = read_uint16(data, i),
				end_vertex    = read_uint16(data, i+2),
				flags         = read_uint16(data, i+4),
				line_type     = read_uint16(data, i+6),
				sector_tag    = read_uint16(data, i+8),
				right_sidedef = read_uint16(data, i+10),
				left_sidedef  = read_uint16(data, i+12))
			self.linedefs.append(linedef)

	def load_sidedefs(self, data):
		# Each sidedef is 30 bytes
		for i in range(0, len(data), 30):
			sidedef = WAD_Sidedef(
				x_offset       = read_int16(data, i),
				y_offset       = read_int16(data, i+2),
				upper_texture  = data[i+4:i+12],
				lower_texture  = data[i+12:i+20],
				middle_texture = data[i+20:i+28],
				sector_id      = read_uint16(data, i+28))
			self.sidedefs.append(sidedef)

	def load_vertexes(self, data):
		# Each vertex is 4 bytes
		for i in range(0, len(data), 4):
			vertex = WAD_Vertex(
				x = read_int16(data, i),
				y = read_int16(data, i+2))
			self.vertexes.append(vertex)

	def load_segs(self, data):
		# Each seg is 12 bytes
		for i in range(0, len(data), 12):
			seg = WAD_Seg(
				start_vertex = read_uint16(data, i),
				end_vertex   = read_uint16(data, i+2),
				angle        = read_uint16(data, i+4),
				linedef_id   = read_uint16(data, i+6),
				direction    = read_uint16(data, i+8),
				offset       = read_uint16(data, i+10))
			self.segs.append(seg)

	def load_subsectors(self, data):
		# Each subsector is 4 bytes
		for i in range(0, len(data), 4):
			subsector = WAD_Subsector(
				seg_count    = read_uint16(data, i),
				first_seg_id = read_uint16(data, i+2))
			self.subsectors.append(subsector)

	def load_nodes(self, data):
		# Each node is 28 bytes
		for i in range(0, len(data), 28):
			node = WAD_Node(
				x_partition  = read_int16(data, i),
				y_partition  = read_int16(data, i+2),
				dx_partition = read_int16(data, i+4),
				dy_partition = read_int16(data, i+6),
				rbox_t       = read_int16(data, i+8),
				rbox_b       = read_int16(data, i+10),
				rbox_l       = read_int16(data, i+12),
				rbox_r       = read_int16(data, i+14),
				lbox_t       = read_int16(data, i+16),
				lbox_b       = read_int16(data, i+18),
				lbox_l       = read_int16(data, i+20),
				lbox_r       = read_int16(data, i+22),
				r_child      = read_uint16(data, i+24),
				l_child      = read_uint16(data, i+26))
			self.nodes.append(node)

	def load_sectors(self, data):
		# Each sector is 26 bytes
		for i in range(0, len(data), 26):
			sector = WAD_Sector(
				floor_height    = read_int16(data, i),
				ceiling_height  = read_int16(data, i+2),
				floor_texture   = data[i+2:i+12],
				ceiling_texture = data[i+12:i+20],
				light_level     = read_int16(data, i+20),
				type_           = read_int16(data, i+22),
				tag             = read_int16(data, i+24))
			self.sectors.append(sector)

	def load_reject(self, data):
		...

	def load_blockmap(self, data):
		...



# Raw objects loaded from the WAD as God intended
class WAD_Thing:
	def __init__(self, x, y, angle, type_, flags):
		self.x = x
		self.y = y
		self.angle = angle
		self.type = type_
		self.flags = flags

class WAD_Linedef:
	def __init__(self,
		start_vertex, end_vertex,
		flags, line_type, sector_tag,
		right_sidedef, left_sidedef
	):
		self.start_vertex = start_vertex
		self.end_vertex = end_vertex
		self.flags = flags
		self.line_type = line_type
		self.sector_tag = sector_tag
		self.right_sidedef = right_sidedef
		self.left_sidedef  = left_sidedef

class WAD_Sidedef:
	def __init__(self,
			x_offset, y_offset,
			upper_texture, lower_texture, middle_texture,
			sector_id
		):
			self.x_offset = x_offset
			self.y_offset = y_offset
			self.upper_texture = upper_texture
			self.lower_texture = lower_texture
			self.middle_texture = middle_texture
			self.sector_id = sector_id

class WAD_Vertex:
	def __init__(self, x, y):
		self.x = x
		self.y = y

class WAD_Seg:
	def __init__(self,
		start_vertex, end_vertex, angle,
		linedef_id, direction, offset
	):
		self.start_vertex = start_vertex
		self.end_vertex = end_vertex
		self.angle = angle
		self.linedef_id = linedef_id
		self.direction = direction
		self.offset = offset

class WAD_Subsector:
	def __init__(self, seg_count, first_seg_id):
		self.seg_count = seg_count
		self.first_seg_id = first_seg_id

class WAD_Node:
	def __init__(self,
		x_partition, y_partition, dx_partition, dy_partition,
		rbox_t, rbox_b, rbox_l, rbox_r,
		lbox_t, lbox_b, lbox_l, lbox_r,
		r_child, l_child
	):
		self.x_partition = x_partition
		self.y_partition = y_partition
		self.dx_partition = dx_partition
		self.dy_partition = dy_partition
		self.rbox_t = rbox_t
		self.rbox_b = rbox_b
		self.rbox_l = rbox_l
		self.rbox_r = rbox_r
		self.lbox_t = lbox_t
		self.lbox_b = lbox_b
		self.lbox_l = lbox_l
		self.lbox_r = lbox_r
		self.r_child = r_child
		self.l_child = l_child

class WAD_Sector:
	def __init__(self,
		floor_height, ceiling_height,
		floor_texture, ceiling_texture,
		light_level, type_, tag
	):
		self.floor_height = floor_height
		self.ceiling_height = ceiling_height
		self.floor_texture = floor_texture
		self.ceiling_texture = ceiling_texture
		self.light_level = light_level
		self.type = type_
		self.tag = tag
