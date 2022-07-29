
import random
import time

from apps.doom.helpers import *



class Map:

	def __init__(self, name, players):
		self.name = name
		self.players = players

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

	# Used to reposition XY coordinates on to the screen
	def update_offset_and_scale(self, screen):
		# Calculate what we need to shift the map by
		self.x_offset = 0
		self.y_offset = 0
		for v in self.vertexes:
			if v.x < self.x_offset: self.x_offset = v.x
			if v.y < self.y_offset: self.y_offset = v.y
		# Invert offset so we can add it to negative values to bring
		#  them above 0
		self.x_offset *= -1
		self.y_offset *= -1

		self.scale_factor = 15

		# Get the screen size so we can draw not upside down
		self.screen_height = screen.height - 1 # -1 bc pixels indexed at 0
	def remap_x_to_screen(self, x):
		postscale_x_offset = 0
		return (x + self.x_offset)//self.scale_factor + postscale_x_offset
	def remap_y_to_screen(self, y):
		postscale_y_offset = 0
		return self.screen_height - (y + self.y_offset)//self.scale_factor + postscale_y_offset


	"""
	All this code has migrated to renderer.py. Leaving here for now as
	a reference

		# # Rendering methods
		# def render_automap(self, screen, player):
		# 	self.update_offset_and_scale(screen)

		# 	# Draw the map!
		# 	self.render_automap_lines(screen)
		# 	self.render_automap_player(screen, player)
		# 	self.render_automap_things(screen)
		# 	self.render_automap_node(screen)

		# 	# Render the subsectors in order
		# 	self.render_bsp_nodes(screen, player)

		# def render_automap_lines(self, screen):
		# 	# Draw all the lines!
		# 	for l in self.linedefs:
		# 		start_vertex = self.vertexes[l.start_vertex]
		# 		end_vertex   = self.vertexes[l.end_vertex]
		# 		screen.draw_line(
		# 			self.remap_x_to_screen(start_vertex.x),
		# 			self.remap_x_to_screen(end_vertex.x),
		# 			self.remap_y_to_screen(start_vertex.y),
		# 			self.remap_y_to_screen(end_vertex.y),
		# 			0x444444)

		# def render_automap_player(self, screen, player):
		# 	# Draw the given player!
		# 	screen.draw_box(
		# 		self.remap_x_to_screen(player.x),
		# 		self.remap_x_to_screen(player.x),
		# 		self.remap_y_to_screen(player.y),
		# 		self.remap_y_to_screen(player.y),
		# 		0xff0000)

		# def render_automap_things(self, screen):
		# 	# Draw the things!
		# 	for t in self.things:
		# 		screen.draw_box(
		# 			self.remap_x_to_screen(t.x),
		# 			self.remap_x_to_screen(t.x),
		# 			self.remap_y_to_screen(t.y),
		# 			self.remap_y_to_screen(t.y),
		# 			0xff00ff)

		# def render_automap_node(self, screen):
		# 	# Draw the root node's splitter and boxes
		# 	n = self.nodes[-1]

		# 	# Right box
		# 	screen.draw_box(
		# 		self.remap_x_to_screen(n.rbox_l),
		# 		self.remap_x_to_screen(n.rbox_r) + 1,
		# 		self.remap_y_to_screen(n.rbox_t),
		# 		self.remap_y_to_screen(n.rbox_b) + 1,
		# 		0x00ff00) # This is fine

		# 	# Left box
		# 	screen.draw_box(
		# 		self.remap_x_to_screen(n.lbox_l),
		# 		self.remap_x_to_screen(n.lbox_r) + 1,
		# 		self.remap_y_to_screen(n.lbox_t),
		# 		self.remap_y_to_screen(n.lbox_b) + 1,
		# 		0xff0000)

		# 	# Draw the splitter
		# 	screen.draw_box(
		# 		self.remap_x_to_screen(n.x_partition),
		# 		self.remap_x_to_screen(n.x_partition + n.dx_partition),
		# 		self.remap_y_to_screen(n.y_partition),
		# 		self.remap_y_to_screen(n.y_partition + n.dy_partition),
		# 		0x0000ff)

		# def is_point_on_left_side(self, x, y, node_id):
		# 	dx = x - self.nodes[node_id].x_partition
		# 	dy = y - self.nodes[node_id].y_partition
		# 	return (
		# 		(dx * self.nodes[node_id].dy_partition)
		# 		- (dy * self.nodes[node_id].dx_partition)
		# 	) <= 0
		# def render_bsp_nodes(self, screen, player, node_id=None):
		# 	# If node id unspecified, start from the root node
		# 	if node_id  == None:
		# 		return self.render_bsp_nodes(screen, player, len(self.nodes)-1)

		# 	# Mask all bits except the last one to check if this is a
		# 	#  subsector
		# 	if node_id & 0x8000:
		# 		self.render_subsector(screen, player, node_id & (~0x8000))
		# 		return

		# 	# Get position of the first player
		# 	x, y = self.players[0].x, self.players[0].y

		# 	if self.is_point_on_left_side(x, y, node_id):
		# 		self.render_bsp_nodes(screen, player, self.nodes[node_id].l_child)
		# 		self.render_bsp_nodes(screen, player, self.nodes[node_id].r_child)
		# 	else:
		# 		self.render_bsp_nodes(screen, player, self.nodes[node_id].r_child)
		# 		self.render_bsp_nodes(screen, player, self.nodes[node_id].l_child)
		# def render_subsector(self, screen, player, subsector_id):
		# 	subsector = self.subsectors[subsector_id]

		# 	for i in range(subsector.seg_count):
		# 		seg = self.segs[subsector.first_seg_id + i]

		# 		renderer = Renderer(None, player, None)
		# 		vertexes = renderer._wall_is_visible(
		# 			v1=self.vertexes[seg.start_vertex],
		# 			v2=self.vertexes[seg.end_vertex])

		# 		# vertexes = player.clip_vertexes_in_fov(
		# 		# 	self.vertexes[seg.start_vertex],
		# 		# 	self.vertexes[seg.end_vertex])
		# 		if vertexes:
		# 			screen.draw_line(
		# 				self.remap_x_to_screen(self.vertexes[seg.start_vertex].x),
		# 				self.remap_x_to_screen(self.vertexes[seg.end_vertex].x),
		# 				self.remap_y_to_screen(self.vertexes[seg.start_vertex].y),
		# 				self.remap_y_to_screen(self.vertexes[seg.end_vertex].y),
		# 				# random.randint(0,0x1000000))
		# 				0xffffff)
		# 			# time.sleep(0.01)
	"""


	# TODO: Move load_ methods elsewhere?
	def load_things(self, data):
		# Each thing is 10 bytes
		for i in range(0, len(data), 10):
			thing = Map_Thing(
				x     = read_int16(data, i),
				y     = read_int16(data, i+2),
				angle = read_uint16(data, i+4),
				type_ = read_uint16(data, i+6),
				flags = read_uint16(data, i+8))

			# If type is 1-4, a player!
			if thing.type in [1,2,3,4]:
				for p in self.players:
					if p.id == thing.type:
						p.update_from_thing(thing)
			else:
				self.things.append(thing)
	def load_linedefs(self, data):
		# Each linedef is 14 bytes
		for i in range(0, len(data), 14):
			linedef = Map_Linedef(
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
			sidedef = Map_SideDef(
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
			vertex = Map_Vertex(
				x = read_int16(data, i),
				y = read_int16(data, i+2))
			self.vertexes.append(vertex)
	def load_segs(self, data):
		# Each seg is 12 bytes
		for i in range(0, len(data), 12):
			seg = Map_Seg(
				start_vertex = read_uint16(data, i),
				end_vertex   = read_uint16(data, i+2),
				angle        = read_uint16(data, i+4),
				linedef_id   = read_uint16(data, i+6),
				direction    = read_uint16(data, i+8),
				offset       = read_uint16(data, i+10))
			self.segs.append(seg)
	def load_ssectors(self, data):
		# Each subsector is 4 bytes
		for i in range(0, len(data), 4):
			subsector = Map_Subsector(
				seg_count    = read_uint16(data, i),
				first_seg_id = read_uint16(data, i+2))
			self.subsectors.append(subsector)
	def load_nodes(self, data):
		# Each node is 28 bytes
		for i in range(0, len(data), 28):
			node = Map_Node(
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
			sector = Map_Sector(
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
	def __init__(self, x, y, angle, type_, flags):
		self.x = x
		self.y = y
		self.angle = angle
		self.type = type_
		self.flags = flags
	def __repr__(self):
		return f"<Thing: pos=({self.x},{self.y}), angle={self.angle}, type={self.type}, flags={self.flags}>"

class Map_Linedef:
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
		self.right_sidedef = right_sidedef if right_sidedef != 0xffff else None
		self.left_sidedef  = left_sidedef  if left_sidedef  != 0xffff else None

class Map_SideDef:
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

class Map_Vertex:
	def __init__(self, x, y):
		self.x = x
		self.y = y
	def __repr__(self):
		return f"<Vertex: ({self.x},{self.y})>"

class Map_Seg:
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

class Map_Subsector:
	def __init__(self, seg_count, first_seg_id):
		self.seg_count = seg_count
		self.first_seg_id = first_seg_id

class Map_Node:
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

class Map_Sector:
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
