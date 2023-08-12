
import numpy as np
import queue
import threading
import time

from apps.generic import AppGeneric

from apps.doom.screen import Screen
from apps.doom.doom_engine import DoomEngine
# from apps.doom.wad import WAD
# from apps.doom.player import Player




class Game:
	"""
	Simple example of a game
	"""
	def __init__(self, screen):
		self.screen = screen

		# Where the top left corner of the flag is
		self.flag_offset_x = 1
		self.flag_offset_y = 1

		self.automap_showing = False
		# self.draw_trans_flag()

		# Start doom engine
		self.doom_engine = DoomEngine(screen)

	def turn_left(self):
		self.doom_engine.player.turn_left()
	def turn_right(self):
		self.doom_engine.player.turn_right()
	def move_forward(self):
		self.doom_engine.player.move_forward()
	def move_backward(self):
		self.doom_engine.player.move_backward()
	def toggle_automap(self):
		self.automap_showing = not self.automap_showing
	def draw_demon(self):
		self.screen.draw_image(20, 20, "apps/doom/Cacodemon_sprite.png")

	def draw_screen(self):
		if self.automap_showing:
			self.doom_engine.draw_automap()
		else:
			self.doom_engine.draw_projection()



class DoomGame(AppGeneric):
	
	def __init__(self, session):
		self.session = session

		# Window size
		self.screen = Screen(
			height=session.config.window_height,
			width=session.config.window_width,
			sender=self.send_CHANNEL_DATA)

		# Key binds
		self.eof_char = None
		self.in_NL = None
		self.out_NL = None
		self.setup_keybinds(session.config)

		# Data used by this app
		self.running = threading.Event()
		self.user_input = queue.Queue()
		self.game = Game(self.screen)

		# Threads used by this app
		self.threads = []


	def setup_keybinds(self, config):
		# Read the client's [CTRL+D] character from config if available
		if config.eof not in [None, 255]: # Set to something valid
			self.eof_char = bytes([config.eof])
		elif config.eof == 255: # Explicitly set as nothing
			self.eof_char = None
		else: # Default value
			self.eof_char = None

		# Handling NL and CR
		if config.icrnl:
			self.in_NL = b"\r"
		else:
			self.in_NL = b"\n"

		if config.onlcr:
			self.out_NL = b"\r\n"
		else:
			self.out_NL = b"\n"


	def start(self):
		# Set up threads
		self.threads = [
			threading.Thread(target=self.user_input_handler),
			threading.Thread(target=self.screen_refresh_loop),
			threading.Thread(target=self.event_loop)
		]
		for t in self.threads:
			t.daemon = True

		# Start threads
		self.running.set()
		for t in self.threads:
			t.start()


	def stop(self):
		# Stops all relevant threads
		self.running.clear()
		for t in self.threads:
			t.join()


	def handle_CHANNEL_DATA(self, msg):
		# Break up incoming data into individual bytes and add to the
		#  user input queue to be handled
		for b in msg.data:
			self.user_input.put(bytes([b]))


	def user_input_handler(self):
		"""
		Handles user input key presses etc
		"""
		while self.running.isSet():
			# Get next key press if available
			try:
				key = self.user_input.get(timeout=0.1)
			except queue.Empty:
				continue

			# Handle special characters set by the terminal config
			if self.eof_char is not None and key == self.eof_char:
				self.handle_key_eof()

			# Handle normal keys
			elif key == b"w": self.handle_key_w()
			elif key == b"a": self.handle_key_a()
			elif key == b"s": self.handle_key_s()
			elif key == b"d": self.handle_key_d()
			elif key == b"e": self.handle_key_e()
			elif key == b"\t": self.handle_key_tab()

			# Unbound keys
			else:
				self.handle_key_unbound(key)

		# After exiting, clear screen and close
		self.screen.close()
		self.send_CHANNEL_CLOSE()


	def screen_refresh_loop(self):
		"""
		Updates the clients screen at the desired refresh rate
		"""
		desired_fps = 30
		desired_delay_between_frame = 1/desired_fps
		last_refresh = 0

		while self.running.isSet():
			t = time.time()

			# If it's already been too long since the last frame
			if t - last_refresh > desired_delay_between_frame:
				# print(f"Behind by {(t - last_refresh)/desired_delay_between_frame - 1} frames")
				self.screen.refresh()

			# Else, we need to wait the remaining time and display after
			else:
				time.sleep(desired_delay_between_frame - (t - last_refresh))
				self.screen.refresh()

			last_refresh = t


	def event_loop(self):
		"""
		Does nothing for now
		"""
		while self.running.isSet():
			# Redraw the map every 2/30
			self.game.draw_screen()
			time.sleep(2/30)


	################
	# KEY HANDLERS #
	################
	def handle_key_eof(self):
		self.running.clear()

	def handle_key_w(self):
		self.game.move_forward()

	def handle_key_a(self):
		self.game.turn_left()

	def handle_key_s(self):
		self.game.move_backward()

	def handle_key_d(self):
		self.game.turn_right()

	def handle_key_e(self):
		self.game.draw_demon()

	def handle_key_tab(self):
		self.game.toggle_automap()

	def handle_key_unbound(self, key):
		print(f"Unhandled key {key}")
