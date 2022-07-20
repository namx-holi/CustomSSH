
import numpy as np
import queue
import random
import threading
import time

from apps.generic import AppGeneric




# ANSI primitives
def ansi_command(cmd):
	return b"\x1b[" + cmd

def ansi_clear():
	return ansi_command(b"2J")

def ansi_reset_colour():
	return ansi_command(b"39m") + ansi_command(b"49m")

def ansi_set_fg_colour(r,g,b):
	return ansi_command(b"38;2;" + f"{r};{g};{b}".encode() + b"m")

def ansi_set_bg_colour(r,g,b):
	return ansi_command(b"48;2;" + f"{r};{g};{b}".encode() + b"m")

def ansi_set_full_colour(fg_r, fg_g, fg_b, bg_r, bg_g, bg_b):
	return ansi_command(
		b"38;2;" + f"{fg_r};{fg_g};{fg_b}".encode() + b";"
		+ b"48;2;" + f"{bg_r};{bg_g};{bg_b}".encode() + b"m")

def ansi_move_cursor(x, y):
	return ansi_command(f"{y};{x}".encode() + b"H")




class Screen:
	# Handles updating pixels only when needed

	def __init__(self, height, width, px=b"  "):
		self.px = px
		self.px_width = len(self.px)

		self.width = width // self.px_width
		self.height = height
		self.canvas = np.zeros((width, height), dtype=int)
		self.pending = np.zeros((width, height), dtype=int)

	def draw_pixel(self, x, y, colour):
		self.pending[x][y] = colour

	def draw_box(self, x1, x2, y1, y2, colour):
		# TODO: Should this +1 to be inclusive?
		self.pending[x1:x2, y1:y2] = colour

	def refresh(self):
		# Find any pixels that have changed
		diff = np.abs(self.pending - self.canvas)
		if np.sum(diff) == 0:
			# No updates required
			return None

		# Need to update pixels that have changed
		# TODO: Find chunks of pixels in a row that are the same and
		#  update those at the same time
		# https://stackoverflow.com/a/53361528 # Promising
		# https://stackoverflow.com/a/64180416 # ???
		# https://stackoverflow.com/a/44791128 # VERY PROMISING !
		# Using above, would first render chunks in the row, then go
		#  back and update the individual pixels for each row?
		data = b""
		diff_pixels = zip(*diff.nonzero())
		for x,y in diff_pixels:
			colour = self.pending[x,y]
			r = (colour & 0xff0000) >> 16
			g = (colour & 0x00ff00) >> 8
			b = colour & 0x0000ff
			data += (
				ansi_move_cursor(x*self.px_width+1,y+1)
				+ ansi_set_bg_colour(r,g,b)
				+ self.px)

		# Update the canvas
		self.canvas[diff != 0] = self.pending[diff != 0]

		return data




# # Rendering
# def draw_pixel(x,y,r,g,b):
# 	# Writes a space with background set to specified colour
# 	return (
# 		ansi_move_cursor(x,y)
# 		+ ansi_set_bg_colour(r,g,b)
# 		+ b" ")

# def draw_box(x1, y1, x2, y2, r, g, b):
# 	# Draws a filled box from x1,y1 to x2,y2
# 	# Move cursor to top left and set colour
# 	msg = b""

# 	# Draw each row
# 	for row in range(y1,y2+1): # +1 for inclusive
# 		# Move to start of that row and set colour
# 		msg += ansi_move_cursor(x1, row) + ansi_set_bg_colour(r,g,b)
		
# 		# Draw row
# 		msg += b" " * (x2-x1+1) # +1 for inclusive
# 	return msg



class DoomGame(AppGeneric):
	
	def __init__(self, session):
		self.session = session

		# Window size
		self.screen = Screen(session.config.height, session.config.width)

		# Key binds
		self.eof_char = None
		self.in_NL = None
		self.out_NL = None
		self.setup_keybinds(session.config)

		# Data used by this app
		self.running = threading.Event()
		self.user_input = queue.Queue()

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
			threading.Thread(target=self.display_loop)
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
		while self.running.isSet():
			# Get next key press if available
			try:
				key = self.user_input.get(timeout=0.1)
			except queue.Empty:
				continue

			print("KEY WAS", key)
			print("EOF is", self.eof_char)

			# If we have received the users EOF, exit
			if self.eof_char is not None and key == self.eof_char:
				print()
				self.running.clear()
				break

			# TODO: Handle other keys
			...

		# After exiting, clear screen and close
		self.send_CHANNEL_DATA(ansi_reset_colour())
		self.send_CHANNEL_DATA(ansi_clear())
		self.send_CHANNEL_CLOSE()


	def display_loop(self):
		# Clear the screen ready
		self.send_CHANNEL_DATA(ansi_clear())

		# Fill screen with pink
		# pink_bg = screen.draw_box(0, 0, self.width-1, self.height-1, 0xfe, 0x21, 0x8b)
		# self.send_CHANNEL_DATA(pink_bg)

		# Draws random pixels between x=0-10 and y=0-10 every second
		while self.running.isSet():
			# Trans flag
			self.screen.draw_box(1, 21,  1,  5, 0x55cdfd) # blue
			self.screen.draw_box(1, 21,  5,  9, 0xf6aab7) # pink
			self.screen.draw_box(1, 21,  9, 13, 0xffffff) # white
			self.screen.draw_box(1, 21, 13, 17, 0xf6aab7) # pink
			self.screen.draw_box(1, 21, 17, 21, 0x55cdfd) # blue
			data = self.screen.refresh()
			if data is not None:
				self.send_CHANNEL_DATA(data)
			time.sleep(1)

			# NB flag
			self.screen.draw_box(1, 21,  1,  6, 0xfcf431) # yellow
			self.screen.draw_box(1, 21,  6, 11, 0xffffff) # white
			self.screen.draw_box(1, 21, 11, 16, 0x9d59d2) # purple
			self.screen.draw_box(1, 21, 16, 21, 0x000000) # black
			data = self.screen.refresh()
			if data is not None:
				self.send_CHANNEL_DATA(data)
			time.sleep(1)
