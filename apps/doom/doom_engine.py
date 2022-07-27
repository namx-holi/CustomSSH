
from apps.doom.player import Player
from apps.doom.wad import WAD
from apps.doom.renderer import Renderer


class DoomEngine:

	def __init__(self, screen):
		# Create players
		self.player = Player(1)
		
		# Load WAD
		self.wad = WAD("apps/doom/doom.wad")
		self.wad.load()

		# Load map
		self.map = self.wad.load_map("E1M1", players=[self.player])
		print(f"Loaded map: {self.map}")

		# Create a renderer
		self.renderer = Renderer(screen, self.player, self.map)


	def draw_automap(self, screen):
		# self.map.render_automap(screen, self.player)
		self.renderer.render_automap()
