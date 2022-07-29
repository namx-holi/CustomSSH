import numpy as np
from apps.doom.helpers import normalise_angle


class Renderer:

	wall_colours = {}


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


	def render_perspective(self):
		# Start a batch render as we don't want to render frames during
		#  drawing this screen
		batch = self.screen.new_batch()

		# Render nodes
		self._render_bsp_nodes(batch)

		# Draw the batch to the screen
		batch.draw()

	def render_automap(self):
		# Start a batch render as we don't want to render frames during
		#  drawing this screen
		batch = self.screen.new_batch()

		# Draw the walls
		for line in self.map.linedefs:
			batch.draw_line(
				self.remap_automap_x_to_screen(line.start_vertex.x),
				self.remap_automap_x_to_screen(line.end_vertex.x),
				self.remap_automap_y_to_screen(line.start_vertex.y),
				self.remap_automap_y_to_screen(line.end_vertex.y),
				0x0000ff)

		# Render the player
		batch.draw_box(
			self.remap_automap_x_to_screen(self.player.x),
			self.remap_automap_x_to_screen(self.player.x),
			self.remap_automap_y_to_screen(self.player.y),
			self.remap_automap_y_to_screen(self.player.y),
			0xff0000)

		# Render all other things on the map
		for t in self.map.things:
			batch.draw_box(
				self.remap_automap_x_to_screen(t.x),
				self.remap_automap_x_to_screen(t.x),
				self.remap_automap_y_to_screen(t.y),
				self.remap_automap_y_to_screen(t.y),
				0xff00ff)

		# Draw the batch to the screen
		batch.draw()


	def _render_bsp_nodes(self, screen, node=None):
		# Start with root node if not specified
		if node is None:
			return self._render_bsp_nodes(screen, self.map.nodes[-1])

		# If the node is a subsector, render it instead of recursing
		if node.is_subsector():
			self._render_subsector(screen, node)
			return

		# Get the position of the player and find the next best node
		x = self.player.x
		y = self.player.y
		if self._is_point_on_left_side(x, y, node):
			# Render the left side first as closest
			self._render_bsp_nodes(screen, node.l_child)
			self._render_bsp_nodes(screen, node.r_child)
		else:
			# Render the right side first as closest
			self._render_bsp_nodes(screen, node.r_child)
			self._render_bsp_nodes(screen, node.l_child)


	def _render_subsector(self, screen, subsector):
		for seg in subsector.segs:
			visible, v1, v2 = self._clip_vertexes_in_fov(seg.start_vertex, seg.end_vertex)

			if visible:
				self.add_wall_in_fov(screen, seg, v1, v2)


	def add_wall_in_fov(self, screen, seg, v1, v2):
		# Solid walls don't have a left side
		if seg.left_sector is None:
			self.add_solid_wall(screen, seg, v1, v2)

	def add_solid_wall(self, screen, seg, v1, v2):
		v1_x_screen = self._angle_to_screen(v1)
		v2_x_screen = self._angle_to_screen(v2)
		# screen.draw_line(v1_x_screen, v1_x_screen, 0, 320, 0xffffff)
		# screen.draw_line(v2_x_screen, v2_x_screen, 0, 320, 0xffffff)

		# TODO: Remove
		# Calculate how far the closest bit of the wall is
		v1_point = seg.start_vertex
		v2_point = seg.end_vertex
		mid_x = (v1_point.x + v2_point.x)/2
		mid_y = (v1_point.y + v2_point.y)/2
		dist = ((mid_x - self.player.x)**2 + (mid_y - self.player.y)**2)**0.5
		FOG_DIST = 1500 # Past this dist is black
		colour_percentage = 1 - np.clip(dist, 0, FOG_DIST)/FOG_DIST
		# Do some maths so that far away looks a lot further away. ie non linear brightness
		colour_percentage = colour_percentage ** 4
		brightness = int(colour_percentage * 0xff)
		colour = brightness * 0x10101 # Turn into a grey

		screen.draw_box(
			v1_x_screen, v2_x_screen, 75, 125,
			colour=colour, fill=True, under=True)


	def _is_point_on_left_side(self, x, y, node):
		# Checks if the given point is on the left partition of the
		#  given node id
		dx = x - node.x_partition
		dy = y - node.y_partition
		return ((dx * node.dy_partition) - (dy * node.dx_partition)) <= 0


	def _vertex_angle_to_player(self, vertex):
		v_dx = vertex.x - self.player.x
		v_dy = vertex.y - self.player.y
		# TODO: Fix this when player angle is set normally
		return normalise_angle(np.rad2deg(np.arctan2(v_dy, v_dx)))


	def _clip_vertexes_in_fov(self, v1, v2):
		V1_angle = self._vertex_angle_to_player(v1)
		V2_angle = self._vertex_angle_to_player(v2)

		V1_to_V2_span = normalise_angle(V1_angle - V2_angle)
		if V1_to_V2_span >= 180:
			return False, None, None

		# Rotate everything around the player
		V1_angle = normalise_angle(V1_angle - self.player.angle)
		V2_angle = normalise_angle(V2_angle - self.player.angle)

		half_fov = self.player.fov / 2

		# Validate and clip V1
		# Shift angles to be between 0 and 90
		# TODO: Handle different FOV
		V1_moved = normalise_angle(V1_angle + half_fov)
		if V1_moved > self.player.fov:
			# Nowe we know that V1 is outside the left side of the FOV
			#  but we need to check is V2 also outside.
			V1_moved_angle = V1_moved - self.player.fov

			# Are v1 and v2 both outside?
			if V1_moved_angle >= V1_to_V2_span:
				return False, None, None

			# At this point, V2 or part of the line should be in the
			#  FOV. We need to clip V1
			V1_angle = normalise_angle(half_fov)

		# Validate and clip V2
		V2_moved = normalise_angle(half_fov - V2_angle)

		# Is V2 outside the FOV?
		if V2_moved > self.player.fov:
			V2_angle = normalise_angle(-half_fov)

		# For some reason we add 90?
		# TODO: Why do we do this?
		V1_angle = normalise_angle(V1_angle + 90)
		V2_angle = normalise_angle(V2_angle + 90)
		return True, V1_angle, V2_angle


	def _angle_to_screen(self, angle):
		iX = 0

		screen_dist = self.screen.width / (2 * np.tan(np.deg2rad(self.player.fov/2)))

		if angle > 90:
			angle = normalise_angle(angle - 90)
			ix = self.screen.width/2 - np.tan(np.deg2rad(angle)) * screen_dist
		else:
			angle = normalise_angle(90 - angle)
			ix = np.tan(np.deg2rad(angle)) * screen_dist + self.screen.width/2

		return int(round(ix))
