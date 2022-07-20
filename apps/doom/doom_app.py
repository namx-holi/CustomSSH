
import numpy as np
import queue
import threading
import time

from apps.generic import AppGeneric
from apps.doom.screen import Screen




class Game:
	"""
	Simple example of a game
	"""
	def __init__(self, screen):
		self.screen = screen

		# Where the top left corner of the flag is
		self.flag_offset_x = 1
		self.flag_offset_y = 1

		self.flag_toggle = False
		self.draw_trans_flag()

	def draw_trans_flag(self):
		self.screen.draw_box( # blue
			 0+self.flag_offset_x, 20+self.flag_offset_x,
			 0+self.flag_offset_y,  4+self.flag_offset_y,
			0x55cdfd)
		self.screen.draw_box( # pink
			 0+self.flag_offset_x, 20+self.flag_offset_x,
			 4+self.flag_offset_y,  8+self.flag_offset_y,
			0xf6aab7)
		self.screen.draw_box( # white
			 0+self.flag_offset_x, 20+self.flag_offset_x,
			 8+self.flag_offset_y, 12+self.flag_offset_y,
			0xffffff)
		self.screen.draw_box( # pink
			 0+self.flag_offset_x, 20+self.flag_offset_x,
			12+self.flag_offset_y, 16+self.flag_offset_y,
			0xf6aab7)
		self.screen.draw_box( # blue
			 0+self.flag_offset_x, 20+self.flag_offset_x,
			16+self.flag_offset_y, 20+self.flag_offset_y,
			0x55cdfd)

	def draw_nb_flag(self):
		self.screen.draw_box( # yellow
			 0+self.flag_offset_x, 20+self.flag_offset_x,
			 0+self.flag_offset_y,  5+self.flag_offset_y,
			0xfcf431)
		self.screen.draw_box( # white
			 0+self.flag_offset_x, 20+self.flag_offset_x,
			 5+self.flag_offset_y, 10+self.flag_offset_y,
			0xffffff)
		self.screen.draw_box( # purple
			 0+self.flag_offset_x, 20+self.flag_offset_x,
			10+self.flag_offset_y, 15+self.flag_offset_y,
			0x9d59d2)
		self.screen.draw_box( # black
			 0+self.flag_offset_x, 20+self.flag_offset_x,
			15+self.flag_offset_y, 20+self.flag_offset_y,
			0x000000)

	def toggle_flag(self):
		if self.flag_toggle:
			self.draw_trans_flag()
		else:
			self.draw_nb_flag()
		self.flag_toggle = not self.flag_toggle

	def move_flag_up(self):
		self.flag_offset_y = np.clip(self.flag_offset_y-1, 1, 100)
	def move_flag_down(self):
		self.flag_offset_y = np.clip(self.flag_offset_y+1, 1, 100)
	def move_flag_left(self):
		self.flag_offset_x = np.clip(self.flag_offset_x-1, 1, 100)
	def move_flag_right(self):
		self.flag_offset_x = np.clip(self.flag_offset_x+1, 1, 100)





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
			elif key == b" ": self.handle_key_space()

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
			time.sleep(1)


	################
	# KEY HANDLERS #
	################
	def handle_key_eof(self):
		self.running.clear()

	def handle_key_w(self):
		self.game.move_flag_up()

	def handle_key_a(self):
		self.game.move_flag_left()

	def handle_key_s(self):
		self.game.move_flag_down()

	def handle_key_d(self):
		self.game.move_flag_right()

	def handle_key_space(self):
		self.game.toggle_flag()

	def handle_key_unbound(self, key):
		print(f"Unhandled key {key}")
