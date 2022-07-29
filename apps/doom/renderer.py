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
			self._render_bsp_nodes(screen, node.r_child)
			self._render_bsp_nodes(screen, node.l_child)
		else:
			# Render the right side first as closest
			self._render_bsp_nodes(screen, node.l_child)
			self._render_bsp_nodes(screen, node.r_child)

	def _render_subsector(self, screen, subsector):
		# For every segment in the subsector, draw it if visible
		for seg in subsector.segs:
			if self._wall_is_visible(seg.start_vertex, seg.end_vertex):
				self._project_wall(screen, seg.start_vertex, seg.end_vertex)

	def _is_point_on_left_side(self, x, y, node):
		# Checks if the given point is on the left partition of the
		#  given node id
		dx = x - node.x_partition
		dy = y - node.y_partition
		return (
			(dx * node.dy_partition)
			- (dy * node.dx_partition)
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


	def _project_wall_old(self, screen, v1, v2):
		# Calculate the angles to v1 and v2 relative to player
		V1 = self._player_rel_angle(v1)
		V2 = self._player_rel_angle(v2)

		# Precalculate the screen distance from triangle made by FOV and
		#  the screen width
		R = self.screen.width/(2*np.tan(np.deg2rad(self.player.fov.angle/2)))

		# Calculate A (how far left of center screen V1 is)
		A = R * np.tan(np.deg2rad(V1))
		# Calculate B (how far right of center screen V2 is)
		B = R * np.tan(np.deg2rad(V2))

		# Calculate the actual screen positions and draw wall
		A_screen = int(round(self.screen.width/2 - A))
		B_screen = int(round(self.screen.width/2 + B))

		# TODO: Remove
		# Calculate how far the closest bit of the wall is
		v1_dist = ((v1.x - self.player.x)**2 + (v1.y - self.player.y)**2)**0.5
		v2_dist = ((v2.x - self.player.x)**2 + (v2.y - self.player.y)**2)**0.5
		dist = min(v1_dist, v2_dist)
		FOG_DIST = 1000 # Past this dist is black
		colour_percentage = 1 - np.clip(dist, 0, FOG_DIST)/FOG_DIST
		brightness = int(colour_percentage * 0xff)
		colour = brightness * 0x10101 # Turn into a grey

		screen.draw_box(
			x1=A_screen, x2=B_screen,
			y1=50, y2=150,
			colour=colour, fill=True)


	def _project_wall(self, screen, v1, v2):
		# Calculate the angles to v1 and v2 relative to player
		V1 = self._player_rel_angle(v1)
		V2 = self._player_rel_angle(v2)
		# print(f"V1={V1}, V2={V2}")

		# Clip the angles so they are in FOV
		half_fov = self.player.fov.angle / 2
		V1 = np.clip(V1, -half_fov, half_fov)
		V2 = np.clip(V2, -half_fov, half_fov)

		# Calculate projection screen distance in units from the player
		screen_dist = self.screen.width / (2 * np.tan(np.deg2rad(half_fov)))

		def _angle_to_screen(angle):
			ix = 0
			# TODO: Why does this work ?????
			if angle < 90:
				# Left side
				ix = self.screen.width/2 - round(np.tan(np.deg2rad(angle)) * screen_dist)
			else:
				# Right side
				ix = round(np.tan(np.deg2rad(angle)) * screen_dist)
				ix += self.screen.width/2
			return int(ix)

		V1_x = _angle_to_screen(V1)
		V2_x = _angle_to_screen(V2)

		# TODO: Remove
		# Calculate how far the closest bit of the wall is
		# v1_dist = ((v1.x - self.player.x)**2 + (v1.y - self.player.y)**2)**0.5
		# v2_dist = ((v2.x - self.player.x)**2 + (v2.y - self.player.y)**2)**0.5
		# dist = min(v1_dist, v2_dist)
		# Calculate the dist from midpoint of the wall
		mid_x = (v1.x + v2.x)/2
		mid_y = (v1.y + v2.y)/2
		dist = ((mid_x - self.player.x)**2 + (mid_y - self.player.y)**2)**0.5
		FOG_DIST = 1000 # Past this dist is black
		colour_percentage = 1 - np.clip(dist, 0, FOG_DIST)/FOG_DIST
		# Do some maths so that far away looks a lot further away. ie non linear brightness
		colour_percentage = colour_percentage ** 4
		brightness = int(colour_percentage * 0xff)
		colour = brightness * 0x10101 # Turn into a grey

		screen.draw_box(
			V1_x, V2_x, 50, 150,
			colour=colour, fill=True)

