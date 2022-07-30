import numpy as np
from apps.doom.helpers import normalise_angle

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


	def _render_subsector(self, screen, subsector):
		for seg in subsector.segs:
			visible, v1_angle, v2_angle = self._clip_vertexes_in_fov(seg.start_vertex, seg.end_vertex)

			if visible:
				self.add_wall_in_fov(screen, seg, v1_angle, v2_angle)


	def add_wall_in_fov(self, screen, seg, v1_angle, v2_angle):
		# Solid walls don't have a left side
		if seg.left_sector is None:
			self.add_solid_wall(screen, seg, v1_angle, v2_angle)

	def add_solid_wall(self, screen, seg, v1_angle, v2_angle):
		v1_x_screen = self._angle_to_screen(v1_angle)
		v2_x_screen = self._angle_to_screen(v2_angle)
		# screen.draw_line(v1_x_screen, v1_x_screen, 0, 320, 0xffffff)
		# screen.draw_line(v2_x_screen, v2_x_screen, 0, 320, 0xffffff)

		# Calculate the wall ceiling and floor points
		(
			ceiling_v1_on_screen, floor_v1_on_screen,
			ceiling_v2_on_screen, floor_v2_on_screen
		) = self.calculate_wall_height_simple(seg, v1_x_screen, v2_x_screen)#, v1_angle, v2_angle)


		# TODO: Remove
		# Calculate how far the midpoint of the wall is
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

		# print("Drawing a polygon")
		# print("  top left",  v1_x_screen, ceiling_v1_on_screen)
		# print("  top right", v2_x_screen, ceiling_v2_on_screen)
		# print("  bot left",  v1_x_screen, floor_v1_on_screen)
		# print("  bot right", v2_x_screen, floor_v2_on_screen)

		# Draw wall wireframe
		screen.draw_line(
			v1_x_screen, v1_x_screen, ceiling_v1_on_screen, floor_v1_on_screen,
			colour=colour, under=True)
		screen.draw_line(
			v2_x_screen, v2_x_screen, ceiling_v2_on_screen, floor_v2_on_screen,
			colour=colour, under=True)
		screen.draw_line(
			v1_x_screen, v2_x_screen, ceiling_v1_on_screen, ceiling_v2_on_screen,
			colour=colour, under=True)
		screen.draw_line(
			v1_x_screen, v2_x_screen, floor_v1_on_screen, floor_v2_on_screen,
			colour=colour, under=True)

		# screen.draw_box(
		# 	v1_x_screen, v2_x_screen, 75, 125,
		# 	colour=colour, fill=True, under=True)
		# screen.draw()
		# time.sleep(1)


	def _is_point_on_left_side(self, x, y, node):
		# Checks if the given point is on the left partition of the
		#  given node id
		dx = x - node.x_partition
		dy = y - node.y_partition
		return ((dx * node.dy_partition) - (dy * node.dx_partition)) <= 0


	def _clip_vertexes_in_fov(self, v1, v2):
		V1_angle = self.player.angle_to_vertex(v1)
		V2_angle = self.player.angle_to_vertex(v2)

		V1_to_V2_span = normalise_angle(V1_angle - V2_angle)
		if V1_to_V2_span >= 180:
			return False, None, None

		# Rotate everything around the player
		V1_angle = normalise_angle(V1_angle - self.player.angle)
		V2_angle = normalise_angle(V2_angle - self.player.angle)

		# Validate and clip V1
		# Shift angles to be between 0 and 90
		# TODO: Handle different FOV
		V1_moved = normalise_angle(V1_angle + self.half_fov)
		if V1_moved > self.player.fov:
			# Nowe we know that V1 is outside the left side of the FOV
			#  but we need to check is V2 also outside.
			V1_moved_angle = V1_moved - self.player.fov

			# Are v1 and v2 both outside?
			if V1_moved_angle >= V1_to_V2_span:
				return False, None, None

			# At this point, V2 or part of the line should be in the
			#  FOV. We need to clip V1
			V1_angle = normalise_angle(self.half_fov)

		# Validate and clip V2
		V2_moved = normalise_angle(self.half_fov - V2_angle)

		# Is V2 outside the FOV?
		if V2_moved > self.player.fov:
			V2_angle = normalise_angle(-self.half_fov)

		# For some reason we add 90?
		# TODO: Why do we do this?
		V1_angle = normalise_angle(V1_angle + 90)
		V2_angle = normalise_angle(V2_angle + 90)
		return True, V1_angle, V2_angle


	def _angle_to_screen(self, angle):
		iX = 0

		if angle > 90:
			angle = normalise_angle(angle - 90)
			ix = self.half_screen_width - np.tan(np.deg2rad(angle)) * self.screen_distance
		else:
			angle = normalise_angle(90 - angle)
			ix = np.tan(np.deg2rad(angle)) * self.screen_distance + self.half_screen_width

		return int(round(ix))









	def calculate_ceiling_floor_height(self, seg, v_x_screen, distance_to_v):
		ceiling = seg.right_sector.ceiling_height - self.player.z
		floor = seg.right_sector.floor_height - self.player.z

		v_screen_angle = self.screen_x_to_angle[v_x_screen]
		distance_v_to_screen = self.screen_distance / np.cos(np.deg2rad(v_screen_angle))

		ceiling_v_on_screen = np.abs(ceiling) * distance_v_to_screen / distance_to_v
		floor_v_on_screen = np.abs(floor) * distance_v_to_screen / distance_to_v

		if ceiling > 0:
			ceiling_v_on_screen = self.half_screen_height - ceiling_v_on_screen
		else:
			ceiling_v_on_screen += self.half_screen_height

		if floor > 0:
			floor_v_on_screen = self.half_screen_height - floor_v_on_screen
		else:
			floor_v_on_screen += self.half_screen_height

		# print("ceil and floor are", ceiling_v_on_screen, floor_v_on_screen)
		return int(ceiling_v_on_screen), int(floor_v_on_screen)


	def calculate_wall_height_simple(self, seg, v1_x_screen, v2_x_screen):
		distance_to_v1 = self.player.distance_to_vertex(seg.start_vertex)
		distance_to_v2 = self.player.distance_to_vertex(seg.end_vertex)

		# TODO: Prevent recalculating this
		v1_angle = self.player.angle_to_vertex(seg.start_vertex)
		v2_angle = self.player.angle_to_vertex(seg.end_vertex)

		# Special case partial seg on the left
		if v1_x_screen <= 0:
			distance_to_v1 = self.partial_seg(seg, v1_angle, v2_angle, distance_to_v1, True)
			# v1_x_screen = 0

		# Special case partial seg on the right
		if v2_x_screen >= self.screen.width - 1:
			distance_to_v2 = self.partial_seg(seg, v1_angle, v2_angle, distance_to_v2, False)
			# v2_x_screen = self.screen.width - 1

		ceiling_v1_on_screen, floor_v1_on_screen = self.calculate_ceiling_floor_height(seg, v1_x_screen, distance_to_v1)
		ceiling_v2_on_screen, floor_v2_on_screen = self.calculate_ceiling_floor_height(seg, v2_x_screen, distance_to_v2)

		return (
			ceiling_v1_on_screen, floor_v1_on_screen,
			ceiling_v2_on_screen, floor_v2_on_screen)


	def partial_seg(self, seg, v1_angle, v2_angle, distance_to_v, is_left_side):
		"""
		Triangle ABC:
			point A = vertex 1
			point B = vertex 2
			point C = player

		Angle@C = span from V1 to V2
		sin(B) / AC(side b) = sin(C) / AB(side c) : sine rule
			-> Angle B
		Angle A = 180 - Angle@B - Angle@C : sum of triangle = 180

		Angle C2 = angle ACX, found using overlap with FOV
		X : Point where FOV intersects AB
		Angle@X = 180 - Angle@A - Angle C2 : sum of triangle = 180

		Then:
			XC / sin(A) = AC / sin(X)

		Where XC is the distance X to the player, i.e. distance_to_v
		"""
		angle_c = normalise_angle(v1_angle - v2_angle)
		side_c = (
			(seg.start_vertex.x - seg.end_vertex.x)**2
			+ (seg.start_vertex.y - seg.end_vertex.y)**2) ** 0.5

		# TODO: Only verified this for if distance_to_v is to V1
		SIN_angle_b = distance_to_v * np.sin(np.deg2rad(angle_c)) / side_c
		angle_b = normalise_angle(np.rad2deg(np.arcsin(SIN_angle_b)))

		# Sum of angles of triangle is 180
		angle_a = normalise_angle(180 - angle_b - angle_c)

		# print("V1 angle is", v1_angle)
		# print("V2 angle is", v2_angle)

		# print("Angle A:", angle_a)
		# print("Angle B:", angle_b)
		# print("Angle C:", angle_c)
		# print("Side C:", side_c)

		# Calculate the point where FOV intersects AB(side c)
		if is_left_side:
			angle_c2 = normalise_angle(v1_angle - (self.player.angle + self.half_fov))
		else:
			angle_c2 = normalise_angle((self.player.angle - self.half_fov) - v2_angle)
		# print("Angle C2", angle_c2)

		# Sum of new triangles angles = 180
		# print("Old dist to v:", distance_to_v)
		angle_x = normalise_angle(180 - angle_a - angle_c2)
		distance_to_v = distance_to_v * np.sin(np.deg2rad(angle_a)) / np.sin(np.deg2rad(angle_x))
		# print("New dist to v:", distance_to_v)
		return distance_to_v






		return













		print("distance_to_v was", distance_to_v)
		dx = seg.start_vertex.x - seg.end_vertex.x
		dy = seg.start_vertex.y - seg.end_vertex.y
		side_c = (dx**2 + dy**2) ** 0.5
		V1_to_V2_span = normalise_angle(v1_angle - v2_angle)
		sine_angle_b = distance_to_v * np.sin(np.deg2rad(V1_to_V2_span)) / side_c
		angle_b = normalise_angle(np.rad2deg(np.arcsin(sine_angle_b)))
		angle_a = normalise_angle(180 - V1_to_V2_span - angle_b)

		if is_left_side:
			angle_v_to_fov = normalise_angle(v1_angle - (self.player.angle + 45))
		else:
			angle_v_to_fov = normalise_angle((self.player.angle - 45) - v2_angle)


		new_angle_b = normalise_angle(180 - angle_v_to_fov - angle_a)
		print("angle a is", angle_a)
		print("angle b is", new_angle_b)
		distance_to_v = distance_to_v * np.sin(np.deg2rad(angle_a)) / np.sin(np.deg2rad(new_angle_b))
		print("angle v to fov is", angle_v_to_fov)
		print("sin angle a is", np.sin(np.deg2rad(angle_a)))
		print("sin angle b is", np.sin(np.deg2rad(new_angle_b)))
		print("distance_to_v is now", distance_to_v)
		return distance_to_v
