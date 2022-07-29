
import math
from apps.doom.helpers import normalise_angle

MOVE_SPEED = 10
TURN_SPEED = 1
EYE_LEVEL = 401 # units


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
		self.angle = normalise_angle(self.angle + TURN_SPEED)
	def turn_right(self):
		self.angle = normalise_angle(self.angle - TURN_SPEED)

	# TODO: Use numpy
	def move_forward(self):
		self.x += math.cos(self.angle * math.pi/180) * MOVE_SPEED
		self.y += math.sin(self.angle * math.pi/180) * MOVE_SPEED
	def move_backward(self):
		self.x -= math.cos(self.angle * math.pi/180) * MOVE_SPEED
		self.y -= math.sin(self.angle * math.pi/180)  * MOVE_SPEED


	def update_from_thing(self, thing):
		self.x = thing.x
		self.y = thing.y
		self.angle = normalise_angle(thing.angle)
