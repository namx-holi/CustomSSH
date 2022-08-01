import numpy as np
from apps.doom.helpers import normalise_angle, Vector

import time



class Renderer:

	wall_colours = {}


	def __init__(self, screen, player, map_):
		self.screen = screen
		self.player = player
		self.map = map_

		# Update the automap scaling etc.
		self.update_automap_offset_and_scale()

		# Used for rendering walls
		self.half_screen_height = self.screen.height / 2
		self.half_screen_width = self.screen.width / 2
		self.half_fov = self.player.fov / 2
		self.screen_distance = self.half_screen_width / np.tan(np.deg2rad(self.half_fov))

		# Precalculate each angle on screen to look up with screen coords
		self.screen_x_to_angle = normalise_angle(
			np.linspace(self.half_fov, -self.half_fov, self.screen.width + 1))


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
		batch.draw_box(0,320,0,200,colour=0x000000,fill=True,under=True)

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


	def _is_point_on_left_side(self, x, y, node):
		# Checks if the given point is on the left partition of the
		#  given node id
		dx = x - node.x_partition
		dy = y - node.y_partition
		return ((dx * node.dy_partition) - (dy * node.dx_partition)) <= 0


	def _render_subsector(self, screen, subsector):
		for seg in subsector.segs:
			v1 = seg.start_vertex
			v2 = seg.end_vertex

			# Check if the wall is visible, and if so, what it's
			#  clipped at within the players FOV
			visible, v1, v2, v1_angle, v2_angle = self._clipped_wall(v1, v2)

			if visible:
				self.add_wall_in_fov(screen, seg, v1, v2, v1_angle, v2_angle)


	def _clipped_wall(self, v1, v2):
		# These angles are relative to the player
		v1_angle = self.player.angle_to_vertex(v1)
		v2_angle = self.player.angle_to_vertex(v2)

		# If the right side of the wall isn't facing us. The first check
		#  with span works for cases when the points are in front of the
		#  player or when they are behind the player but on the same
		#  side. The second check is for the special case when V1 is
		#  behind the player to the left and V2 is behind the player and
		#  to the right.
		v1_to_v2_span = v1_angle - v2_angle
		if v1_to_v2_span <= 0:
			return False, None, None, None, None
		if v1_angle > 90 and v2_angle < -90:
			return False, None, None, None, None

		# Check if both V1 and V2 are outside the FOV
		if v1_angle > self.half_fov and v2_angle > self.half_fov:
			return False, None, None, None, None
		elif v1_angle < -self.half_fov and v2_angle < -self.half_fov:
			return False, None, None, None, None

		# If V1 is too far left, must clip it
		if v1_angle > self.half_fov:
			left_fov_angle = self.player.angle + self.half_fov
			v1 = self.calculate_fov_intersection(v1, v2, left_fov_angle)
			v1_angle = self.half_fov

		# If V2 is too far left, must clip it
		if v2_angle < -self.half_fov:
			right_fov_angle = self.player.angle - self.half_fov
			v2 = self.calculate_fov_intersection(v1, v2, right_fov_angle)
			v2_angle = -self.half_fov

		return True, v1, v2, v1_angle, v2_angle


	def calculate_fov_intersection(self, v1, v2, fov_angle):
		# Uses Cramer's Rule
		fov_vector = Vector(
			np.cos(np.deg2rad(fov_angle)),
			np.sin(np.deg2rad(fov_angle)))

		# Turn the wall points and player pos into vectors
		v1 = Vector(v1.x, v1.y)
		v2 = Vector(v2.x, v2.y)
		player_pos = Vector(self.player.x, self.player.y)

		# Calculate intersection
		R = v2 - v1
		u = (v1 - player_pos).cross(R) / fov_vector.cross(R)
		return player_pos + fov_vector*u


	def add_wall_in_fov(self, screen, seg, v1, v2, v1_angle, v2_angle):
		# Solid walls don't have a left side
		if seg.left_sector is None:
			self.add_solid_wall(screen, seg, v1, v2, v1_angle, v2_angle)


	def get_wall_colour(self, v1, v2):
		# Basic method that gets a shade of grey for the segment,
		#  brighter if close and darker if far. Uses the midpoint for
		#  distance,
		mid_x = (v1.x + v2.x)/2
		mid_y = (v1.y + v2.y)/2
		dist = ((mid_x - self.player.x)**2 + (mid_y - self.player.y)**2) ** 0.5

		FOG_DIST = 1500 # Past this distance is black
		colour_percentage = 1 - np.clip(dist, 0, FOG_DIST)/FOG_DIST

		# Make brightness scale non linear
		colour_percentage = colour_percentage ** 4

		# Calculate brightness of RGB
		brightness = int(colour_percentage * 0xff) * 0x10101
		return brightness


	def add_solid_wall(self, screen, seg, v1, v2, v1_angle, v2_angle):
		v1_angle = normalise_angle(v1_angle)
		v2_angle = normalise_angle(v2_angle)

		# Calculate the widths on screen of each edge of the wall
		v1_x = self._angle_to_screen_width(v1_angle)
		v2_x = self._angle_to_screen_width(v2_angle)

		# Fetch the relative wall heights to the player
		ceiling_height = seg.right_sector.ceiling_height - self.player.z
		floor_height   = seg.right_sector.floor_height   - self.player.z

		# Calculate the heights on screen of each corner of the wall
		v1_ceiling_y, v1_floor_y = self.calculate_wall_screen_heights(
			ceiling_height, floor_height, v1, v1_angle)
		v2_ceiling_y, v2_floor_y = self.calculate_wall_screen_heights(
			ceiling_height, floor_height, v2, v2_angle)

		# Get the colour of the wall
		colour = self.get_wall_colour(v1, v2)

		# Draw wall wireframe
		screen.draw_line(v1_x, v1_x, v1_ceiling_y, v1_floor_y, colour=colour, under=True)
		screen.draw_line(v2_x, v2_x, v2_ceiling_y, v2_floor_y, colour=colour, under=True)
		screen.draw_line(v1_x, v2_x, v1_ceiling_y, v2_ceiling_y, colour=colour, under=True)
		screen.draw_line(v1_x, v2_x, v1_floor_y, v2_floor_y, colour=colour, under=True)

		# screen.draw()
		# time.sleep(1)


	def calculate_wall_screen_heights(self, ceiling_height, floor_height, v, v_angle):
		# Calculate the distance to the vertex
		v_dist = self.player.distance_to_vertex(v)

		# Calculate the distance the point is from the screen
		v_screen_dist = self.screen_distance / np.cos(np.deg2rad(v_angle))

		# Calculate ceiling heights and floor heights
		v_ceiling_y = abs(ceiling_height) * v_screen_dist / v_dist
		v_floor_y   = abs(floor_height)   * v_screen_dist / v_dist

		# Readjust the ceiling to fit on screen
		if ceiling_height > 0:
			v_ceiling_y = self.half_screen_height - v_ceiling_y
		else:
			v_ceiling_y += self.half_screen_height

		# Similarly for the floor
		if floor_height > 0:
			v_floor_y = self.half_screen_height - v_floor_y
		else:
			v_floor_y += self.half_screen_height

		# Return the screen heights as integers
		return int(round(v_ceiling_y)), int(round(v_floor_y))


	def _angle_to_screen_width(self, angle):
		ix = self.half_screen_width - np.tan(np.deg2rad(angle)) * self.screen_distance
		return int(round(ix))
