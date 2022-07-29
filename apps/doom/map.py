
import random
import time

from apps.doom.helpers import *



class Map:

	def __init__(self, wad, name, players):
		self.name = name
		self.players = players

		# Objects present in the map
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

		# Screen drawing details
		self.x_offset = 0
		self.y_offset = 0
		self.scale_factor = 1

		# Load all objects from the given WAD
		self.load_from_wad(wad)


	#################################################
	# Load methods for loading WAD objects into Map #
	#################################################
	def load_from_wad(self, wad):
		self.load_things_from_wad(wad)
		self.load_sectors_from_wad(wad)
		self.load_sidedefs_from_wad(wad)
		self.load_vertexes_from_wad(wad)
		self.load_linedefs_from_wad(wad)
		self.load_segs_from_wad(wad)
		self.load_subsectors_from_wad(wad)
		self.load_nodes_from_wad(wad)

	def load_things_from_wad(self, wad):
		for wad_thing in wad.things:
			thing = Map_Thing(wad_thing)

			# If a player, instead of storing as a thing, update the
			#  player
			if thing.is_player():
				# Find the right player to update
				for p in self.players:
					if p.id == thing.type:
						p.update_from_thing(thing)
			else:
				self.things.append(thing)

	def load_sectors_from_wad(self, wad):
		for wad_sector in wad.sectors:
			sector = Map_Sector(wad_sector)
			self.sectors.append(sector)

	def load_sidedefs_from_wad(self, wad):
		for wad_sidedef in wad.sidedefs:
			sidedef = Map_Sidedef(wad_sidedef, self.sectors)
			self.sidedefs.append(sidedef)

	def load_vertexes_from_wad(self, wad):
		for wad_vertex in wad.vertexes:
			vertex = Map_Vertex(wad_vertex)
			self.vertexes.append(vertex)

	def load_linedefs_from_wad(self, wad):
		for wad_linedef in wad.linedefs:
			linedef = Map_Linedef(wad_linedef, self.sectors, self.sidedefs, self.vertexes)
			self.linedefs.append(linedef)

	def load_segs_from_wad(self, wad):
		for wad_seg in wad.segs:
			seg = Map_Seg(wad_seg, self.vertexes, self.linedefs)
			self.segs.append(seg)

	def load_subsectors_from_wad(self, wad):
		for wad_subsector in wad.subsectors:
			subsector = Map_Subsector(wad_subsector, self.segs)
			self.subsectors.append(subsector)

	def load_nodes_from_wad(self, wad):
		for wad_node in wad.nodes:
			node = Map_Node(wad_node)
			self.nodes.append(node)
		for node in self.nodes:
			node.link_nodes(self.nodes, self.subsectors)


	def __repr__(self):
		return (
			f"<Map {self.name}: "
			+ f"{len(self.players)} players, "
			+ f"{len(self.things)} things, "
			+ f"{len(self.linedefs)} linedefs, "
			+ f"{len(self.sidedefs)} sidedefs, "
			+ f"{len(self.vertexes)} vertexes, "
			+ f"{len(self.segs)} segs, "
			+ f"{len(self.subsectors)} ssectors, "
			+ f"{len(self.nodes)} nodes, "
			+ f"{len(self.sectors)} sectors, "
			+ f"0 reject, "
			+ f"0 blockmap>")



class Map_Thing:
	def __init__(self, wad_thing):
		self.x = wad_thing.x
		self.y = wad_thing.y
		self.angle = wad_thing.angle
		self.type = wad_thing.type
		self.flags = wad_thing.flags

	def is_player(self):
		# Things with a type of Player 1, Player 2, etc
		return self.type in [1,2,3,4]

class Map_Sector:
	def __init__(self, wad_sector):
		self.floor_height = wad_sector.floor_height,
		self.ceiling_height = wad_sector.ceiling_height,
		self.floor_texture = wad_sector.floor_texture,
		self.ceiling_texture = wad_sector.ceiling_texture,
		self.light_level = wad_sector.light_level,
		self.type = wad_sector.type,
		self.tag = wad_sector.tag

class Map_Sidedef:
	def __init__(self, wad_sidedef, sectors):
		self.x_offset = wad_sidedef.x_offset
		self.y_offset = wad_sidedef.y_offset
		self.upper_texture = wad_sidedef.upper_texture
		self.lower_texture = wad_sidedef.lower_texture
		self.middle_texture = wad_sidedef.middle_texture
		self.sector = sectors[wad_sidedef.sector_id]

class Map_Vertex:
	def __init__(self, wad_vertex):
		self.x = wad_vertex.x
		self.y = wad_vertex.y

class Map_Linedef:
	def __init__(self, wad_linedef, sectors, sidedefs, vertexes):
		self.start_vertex = vertexes[wad_linedef.start_vertex]
		self.end_vertex = vertexes[wad_linedef.end_vertex]
		self.flags = wad_linedef.flags
		self.line_type = wad_linedef.line_type

		for sector in sectors:
			if sector.tag == wad_linedef.sector_tag:
				self.sector = sector
				break

		if wad_linedef.right_sidedef != 0xffff:
			self.right_sidedef = sidedefs[wad_linedef.right_sidedef]
		else:
			self.right_sidedef = None

		if wad_linedef.left_sidedef != 0xffff:
			self.left_sidedef = sidedefs[wad_linedef.left_sidedef]
		else:
			self.left_sidedef = None

class Map_Seg:
	def __init__(self, wad_seg, vertexes, linedefs):
		self.start_vertex = vertexes[wad_seg.start_vertex]
		self.end_vertex = vertexes[wad_seg.end_vertex]
		self.angle = wad_seg.angle
		self.linedef = linedefs[wad_seg.linedef_id]
		self.direction = wad_seg.direction
		self.offset = wad_seg.offset

class Map_Subsector:
	def __init__(self, wad_subsector, segs):
		start_seg = wad_subsector.first_seg_id
		end_seg = start_seg + wad_subsector.seg_count
		self.segs = segs[start_seg:end_seg]

	def is_subsector(self):
		# Useful when traversing binary space partitioning tree
		return True

	def __repr__(self):
		return f"<Subsector: {len(self.segs)} segs>"

class Map_Node:
	def __init__(self, wad_node):
		self.x_partition = wad_node.x_partition
		self.y_partition = wad_node.y_partition
		self.dx_partition = wad_node.dx_partition
		self.dy_partition = wad_node.dy_partition
		self.rbox_t = wad_node.rbox_t
		self.rbox_b = wad_node.rbox_b
		self.rbox_l = wad_node.rbox_l
		self.rbox_r = wad_node.rbox_r
		self.lbox_t = wad_node.lbox_t
		self.lbox_b = wad_node.lbox_b
		self.lbox_l = wad_node.lbox_l
		self.lbox_r = wad_node.lbox_r
		self.r_child = wad_node.r_child # id, make reference
		self.l_child = wad_node.l_child # id, make reference

	def link_nodes(self, nodes, subsectors):
		# If right child is a leaf node
		if self.r_child & 0x8000:
			self.r_child = subsectors[self.r_child & (~0x8000)]
		else:
			self.r_child = nodes[self.r_child]

		# If left child is a leaf node
		if self.l_child & 0x8000:
			self.l_child = subsectors[self.l_child & (~0x8000)]
		else:
			self.l_child = nodes[self.l_child]

	def is_subsector(self):
		# Useful when traversing binary space partitioning tree
		return False

	def __repr__(self):
		if isinstance(self.r_child, Map_Node) and isinstance(self.l_child, Map_Node):
			return f"<Node: r_child=<Node ??>, l_child=<Node ??>>"
		elif isinstance(self.r_child, Map_Node):
			return f"<Node: r_child=<Node ??>, l_child={self.l_child}>"
		elif isinstance(self.l_child, Map_Node):
			return f"<Node: r_child={self.r_child}, l_child=<Node ??>>"
		return f"<Node: r_child={self.r_child}, l_child={self.l_child}>"
