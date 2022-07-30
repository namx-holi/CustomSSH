
import math
import numpy as np
from apps.doom.helpers import normalise_angle

MOVE_SPEED = 10
TURN_SPEED = 1
EYE_LEVEL = 41 # units


class Player:
	def __init__(self, id_):
		self.id = id_
		self._x = None
		self._y = None
		self.angle = None
		self.fov = 90 # degrees


	@property
	def x(self):
		return int(self._x)
	@x.setter
	def x(self, val):
		self._x = val

	@property
	def y(self):
		return int(self._y)
	@y.setter
	def y(self, val):
		self._y = val

	@property
	def z(self):
		return EYE_LEVEL



	def turn_left(self):
		self.angle = normalise_angle(self.angle + TURN_SPEED)
		print(self.angle)
	def turn_right(self):
		self.angle = normalise_angle(self.angle - TURN_SPEED)
		print(self.angle)

	# TODO: Use numpy
	def move_forward(self):
		self.x += np.cos(np.deg2rad(self.angle)) * MOVE_SPEED
		self.y += np.sin(np.deg2rad(self.angle)) * MOVE_SPEED
		print(self.x, self.y)
	def move_backward(self):
		self.x -= np.cos(np.deg2rad(self.angle)) * MOVE_SPEED
		self.y -= np.sin(np.deg2rad(self.angle)) * MOVE_SPEED
		print(self.x, self.y)


	def update_from_thing(self, thing):
		self.x = thing.x
		self.y = thing.y
		self.angle = normalise_angle(thing.angle)

		# Debug
		self.x = 815
		self.y = -3152
		self.angle = normalise_angle(200)


	def angle_to_vertex(self, vertex):
		v_dx = vertex.x - self.x
		v_dy = vertex.y - self.y
		return normalise_angle(np.rad2deg(np.arctan2(v_dy, v_dx)))

	def distance_to_vertex(self, vertex):
		v_dx = vertex.x - self.x
		v_dy = vertex.y - self.y
		return (v_dx**2 + v_dy**2) ** 0.5
