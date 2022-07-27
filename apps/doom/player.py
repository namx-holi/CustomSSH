
import math
from apps.doom.helpers import Angle

MOVE_SPEED = 10
TURN_SPEED = 10


class Player:
	def __init__(self, id_):
		self.id = id_
		self._x = None
		self._y = None
		self.angle = None

		self.fov = Angle(90)


	@property
	def x(self):
		return int(self._x)
	@property
	def y(self):
		return int(self._y)
	@x.setter
	def x(self, val):
		self._x = val
	@y.setter
	def y(self, val):
		self._y = val


	def turn_left(self):
		self.angle += TURN_SPEED
	def turn_right(self):
		self.angle -= TURN_SPEED
	def move_forward(self):
		self.x += math.cos(self.angle.angle * math.pi/180) * MOVE_SPEED
		self.y += math.sin(self.angle.angle * math.pi/180) * MOVE_SPEED
	def move_backward(self):
		self.x -= math.cos(self.angle.angle * math.pi/180) * MOVE_SPEED
		self.y -= math.sin(self.angle.angle * math.pi/180)  * MOVE_SPEED


	def update_from_thing(self, thing):
		self.x = thing.x
		self.y = thing.y
		self.angle = Angle(thing.angle)

	def angle_to_vertex(self, vertex):
		v_dx = vertex.x - self.x
		v_dy = vertex.y - self.y
		return Angle(math.atan2(v_dy, v_dx) * 180/math.pi)

	def clip_vertexes_in_fov(self, v1, v2): # Returns new vertexes clipped
		v1_angle = self.angle_to_vertex(v1)
		v2_angle = self.angle_to_vertex(v2)

		# If the wall is not facing the player (only right side of
		#  v1->v2 is visible on a wall), don't return any angles
		v1_to_v2_span = v1_angle - v2_angle
		if v1_to_v2_span >= 180:
			return None

		# Normalise all angles with respect to the player
		v1_angle = v1_angle - self.angle
		v2_angle = v2_angle - self.angle

		# Precalculate half of the field of view
		half_fov = self.fov / 2

		# Validate and clip v1
		# Rotate angles such that border of FOV is border of top right quadrant
		v1_moved = v1_angle + half_fov
		if v1_moved > self.fov: # If outside left FOV
			# Now we know that v1 is outside the left side of the FOV.
			#  But we need to check if v2 is also outside. Let's try
			#  find out what is ithe size of the angle outside the FOV
			v1_moved_angle = v1_moved - self.fov

			# Are both v1 and v2 outside?
			if v1_moved_angle >= v1_to_v2_span:
				return None

			# A this point v2 or part of the line should be in FOV. We
			#  need to clip the v1.
			v1_angle = half_fov

		# Validate and clip v2
		v2_moved = half_fov - v2_angle
		if v2_moved > self.fov: # If outside right FOV
			v2_angle = -half_fov

		v1_angle += 90
		v2_angle += 90
		return [v1_angle, v2_angle]
