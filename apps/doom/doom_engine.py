
from apps.doom.player import Player
from apps.doom.wad import WAD


class DoomEngine:

	def __init__(self):
		# Create players
		self.player = Player(1)
		
		# Load WAD
		self.wad = WAD("apps/doom/doom.wad")
		self.wad.load()

		# Load map
		self.map = self.wad.load_map("E1M1", players=[self.player])
		print(f"Loaded map: {self.map}")


	def draw_automap(self, screen):
		self.map.render_automap(screen)
