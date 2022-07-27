import numpy as np


def normalise_angle(a):
	"""
	Adjusts an angle to be within the range [-180, 180]
	"""
	return (a + 180) % 360 - 180



class Renderer:
	def __init__(self, screen, player, map_):
		self.screen = screen
		self.player = player
		self.map = map_

		# Update the automap scaling etc.
		self.update_automap_offset_and_scale()


	def update_automap_offset_and_scale(self):
		# Calculate what we need to shift the vertexes of the map by so
		#  that it can be displayed on screen
		self._automap_x_offset = 0
		self._automap_y_offset = 0
		for v in self.map.vertexes:
			if v.x < self._automap_x_offset: self._automap_x_offset = v.x
			if v.y < self._automap_y_offset: self._automap_y_offset = v.y

		# Invert the offsets so we can add these numbers to screen coords
		self._automap_x_offset *= -1
		self._automap_y_offset *= -1

		# Set the map scale
		self._automap_scale_factor = 15


	def remap_automap_x_to_screen(self, x):
		return (x + self._automap_x_offset) // self._automap_scale_factor
	def remap_automap_y_to_screen(self, y):
		# -1 because pixels are indexed from zero, and screen height is
		#  total number of pixels in height
		return self.screen.height - (y + self._automap_y_offset) // self._automap_scale_factor - 1


	def render_automap(self):
		# Render the player
		self.screen.draw_box(
			self.remap_automap_x_to_screen(self.player.x),
			self.remap_automap_x_to_screen(self.player.x),
			self.remap_automap_y_to_screen(self.player.y),
			self.remap_automap_y_to_screen(self.player.y),
			0xff0000)

		# Render all other things on the map
		for t in self.map.things:
			self.screen.draw_box(
				self.remap_automap_x_to_screen(t.x),
				self.remap_automap_x_to_screen(t.x),
				self.remap_automap_y_to_screen(t.y),
				self.remap_automap_y_to_screen(t.y),
				0xff00ff)

		# Render nodes
		self._render_bsp_nodes()


	def _render_bsp_nodes(self, node_id=None):
		# Start with root node if not specified
		if node_id is None:
			return self._render_bsp_nodes(len(self.map.nodes)-1)

		# Mask all bits except the last one to check if this is a
		#  subsector
		if node_id & 0x8000:
			self._render_subsector(node_id & (~0x8000))
			return

		# Get the position of the player and find the next best node
		x = self.player.x
		y = self.player.y
		if self._is_point_on_left_side(x, y, node_id):
			# Render the left side first as closest
			self._render_bsp_nodes(self.map.nodes[node_id].l_child)
			self._render_bsp_nodes(self.map.nodes[node_id].r_child)
		else:
			# Render the right side first as closest
			self._render_bsp_nodes(self.map.nodes[node_id].r_child)
			self._render_bsp_nodes(self.map.nodes[node_id].l_child)

	def _render_subsector(self, subsector_id):
		# Get the actual subsector
		subsector = self.map.subsectors[subsector_id]

		# For every segment in the subsector, draw it if visible
		for i in range(subsector.seg_count):
			seg = self.map.segs[subsector.first_seg_id + i]

			if self._wall_is_visible(
				v1=self.map.vertexes[seg.start_vertex],
				v2=self.map.vertexes[seg.end_vertex]
			):
				self.screen.draw_line(
					self.remap_automap_x_to_screen(self.map.vertexes[seg.start_vertex].x),
					self.remap_automap_x_to_screen(self.map.vertexes[seg.end_vertex].x),
					self.remap_automap_y_to_screen(self.map.vertexes[seg.start_vertex].y),
					self.remap_automap_y_to_screen(self.map.vertexes[seg.end_vertex].y),
					0xffffff)

	def _is_point_on_left_side(self, x, y, node_id):
		# Checks if the given point is on the left partition of the
		#  given node id
		dx = x - self.map.nodes[node_id].x_partition
		dy = y - self.map.nodes[node_id].y_partition
		return (
			(dx * self.map.nodes[node_id].dy_partition)
			- (dy * self.map.nodes[node_id].dx_partition)
		) <= 0





	def _player_rel_angle(self, vertex):
		v_dx = vertex.x - self.player.x
		v_dy = vertex.y - self.player.y
		# TODO: get the players angle
		player_angle = normalise_angle(self.player.angle.angle)
		return normalise_angle(np.rad2deg(np.arctan2(v_dy, v_dx)) - player_angle)


	def _wall_is_visible(self, v1, v2):
		# Calculate the angles to v1 and v2 relative to player
		V1 = self._player_rel_angle(v1)
		V2 = self._player_rel_angle(v2)

		# If v1 - v2 is less than zero, wall is not facing us as only
		#  right side going from v1->v2 is visible.
		if normalise_angle(V1 - V2) < 0:
			return False

		# Precalculate half the FOV
		half_fov = self.player.fov.angle / 2 # No need to normalise, FOV in [0, 180]

		# If the right side of the wall is too far left, don't show
		if V2 > half_fov:
			return False

		# If the left side of the wall is too far right, dont' show
		if V1 < -half_fov:
			return False

		return True
