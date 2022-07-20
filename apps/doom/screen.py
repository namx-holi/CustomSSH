
import numpy as np


# ANSI primitives
def ansi_command(cmd):
	return b"\x1b[" + cmd

def ansi_clear():
	return ansi_command(b"2J")

def ansi_reset_colour():
	return ansi_command(b"39m") + ansi_command(b"49m")

def ansi_set_fg_colour(colour):
	r = (colour & 0xff0000) >> 16
	g = (colour & 0x00ff00) >> 8
	b = colour & 0x0000ff
	return ansi_command(b"38;2;" + f"{r};{g};{b}".encode() + b"m")

def ansi_set_bg_colour(colour):
	r = (colour & 0xff0000) >> 16
	g = (colour & 0x00ff00) >> 8
	b = colour & 0x0000ff
	return ansi_command(b"48;2;" + f"{r};{g};{b}".encode() + b"m")

def ansi_set_full_colour(fg_colour, bg_colour):
	fg_r = (fg_colour & 0xff0000) >> 16
	fg_g = (fg_colour & 0x00ff00) >> 8
	fg_b = fg_colour & 0x0000ff
	bg_r = (bg_colour & 0xff0000) >> 16
	bg_g = (bg_colour & 0x00ff00) >> 8
	bg_b = bg_colour & 0x0000ff
	return ansi_command(
		b"38;2;" + f"{fg_r};{fg_g};{fg_b}".encode() + b";"
		+ b"48;2;" + f"{bg_r};{bg_g};{bg_b}".encode() + b"m")

def ansi_move_cursor(x, y):
	return ansi_command(f"{y+1};{x+1}".encode() + b"H")




class Screen:
	# Handles updating pixels only when needed

	def __init__(self, height, width, sender, px=b"  "):
		self.px = px
		self.px_width = len(self.px)

		self.width = width // self.px_width
		self.height = height
		self.canvas = np.zeros((self.height, self.width), dtype=int)
		self.pending = np.empty((self.height, self.width), dtype=int)
		self.pending[:] = -1

		# Data will be sent by calling this sender
		self.sender = sender

		# Clear the screen to start off
		self.clear()


	def draw_pixel(self, x, y, colour):
		# Draws a single pixel in a colour
		self.pending[y,x] = colour


	def draw_box(self, x1, x2, y1, y2, colour):
		# Draws a filled box from (x1,y1) to (x2,y2) in a colour
		# TODO: Should this +1 to be inclusive?
		self.pending[y1:y2, x1:x2] = colour


	def refresh(self):
		# TODO: Find a way to find chunks of the same colour faster
		# https://stackoverflow.com/a/53361528 # Promising
		# https://stackoverflow.com/a/64180416 # ???
		# https://stackoverflow.com/a/44791128 # VERY PROMISING !

		# pending != -1 is used to find actual pending changes and is
		#  multiplied by the actual diff to filter for only actual
		#  changes (!=-1 returns bools that can be used as 0 or 1)
		diff = (self.pending != -1) * (self.canvas - self.pending)
		if np.sum(diff) == 0:
			# No updates required
			return

		# Go through each row as writing a row can be as easy as setting
		#  a colour and sending lots of spaces.
		data = b""

		last_row = None
		last_col = None
		last_colour = None

		# Get only pixels that have changed, and the locations of those changes
		# TODO: Exclude overwriting?
		for row, col in zip(*np.where(diff != 0)):
			colour = self.pending[row,col]

			# If we are in the same row, last col+1, and same colour
			if row == last_row and col-1 == last_col and colour == last_colour:
				# We can just continue on from the last pixel as it's the same
				data += self.px

			# If we are in the same row, last col+1, but different colour
			elif row == last_row and col-1 == last_col:
				# Need to set new colour and then print the pixel
				data += ansi_set_bg_colour(colour) + self.px

			# If we have skipped any columns or rows, but kept the colour
			elif colour == last_colour:
				# We must move the cursor and draw pixel
				data += ansi_move_cursor(col*self.px_width, row) + self.px

			# If we have skipped any columsn or rows, and new colour
			else:
				# We must move the cursor, update colour, then draw px
				data += ansi_move_cursor(col*self.px_width, row) + ansi_set_bg_colour(colour) + self.px

			# Update the last_ variables
			last_row = row
			last_col = col
			last_colour = colour

		# Update the canvas and reset the pending
		self.canvas[diff != 0] = self.pending[diff != 0]
		self.pending[:] = -1

		# Send off the changes to client's screen
		self.sender(data)


	def clear(self):
		self.canvas[:,:] = 0
		self.pending[:,:] = 0
		self.sender(ansi_clear())


	def close(self):
		self.sender(ansi_reset_colour() + ansi_clear() + ansi_move_cursor(0,0))


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


