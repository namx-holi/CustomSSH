
class Player:
	def __init__(self, id_):
		self.id = id_
		self.x = None
		self.y = None
		self.angle = None

	def update_from_thing(self, thing):
		self.x = thing.x
		self.y = thing.y
		self.angle = thing.angle
