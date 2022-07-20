
import numpy as np


# ANSI primitives
def ansi_command(cmd):
	return "\x1b[" + cmd

def ansi_clear():
	return ansi_command("2J")

def ansi_reset_colour():
	return ansi_command("39m") + ansi_command("49m")

def ansi_set_fg_colour(colour):
	r = (colour & 0xff0000) >> 16
	g = (colour & 0x00ff00) >> 8
	b = colour & 0x0000ff
	return ansi_command("38;2;" + f"{r};{g};{b}" + "m")

def ansi_set_bg_colour(colour):
	r = (colour & 0xff0000) >> 16
	g = (colour & 0x00ff00) >> 8
	b = colour & 0x0000ff
	return ansi_command("48;2;" + f"{r};{g};{b}" + "m")

def ansi_set_full_colour(fg_colour, bg_colour):
	fg_r = (fg_colour & 0xff0000) >> 16
	fg_g = (fg_colour & 0x00ff00) >> 8
	fg_b = fg_colour & 0x0000ff
	bg_r = (bg_colour & 0xff0000) >> 16
	bg_g = (bg_colour & 0x00ff00) >> 8
	bg_b = bg_colour & 0x0000ff
	return ansi_command(
		"38;2;" + f"{fg_r};{fg_g};{fg_b}" + ";"
		+ "48;2;" + f"{bg_r};{bg_g};{bg_b}" + "m")

def ansi_move_cursor(x, y):
	return ansi_command(f"{y+1};{x+1}" + "H")



class Screen:
	# Handles updating pixels only when needed. Uses block elements to
	#  draw two pixels per character

	def __init__(self, height, width, sender):
		# The char will be used for upper half, and bg for lower half
		self.px = "▀"

		# Used to signify no update in pending
		self.NO_CHANGE = -1

		self.width  = width
		self.height = height*2

		self.canvas  = np.zeros((self.height, self.width), dtype=int)
		self.pending = np.empty((self.height, self.width), dtype=int)

		self.pending[:] = self.NO_CHANGE

		# Data will be sent to the client by calling this sender
		self.sender = sender

		# Clear the screen to start off, then fill it with black.
		self.clear()
		self.draw_box(0,self.width,0,self.height, 0x333333)
		self.refresh()


	def draw_pixel(self, x, y, colour):
		# Sets one pixel in the pending view
		self.pending[y,x] = colour


	def draw_box(self, x1, x2, y1, y2, colour):
		# Draws a filled box from (x1,y1) to (x2,y2) in a colour
		# TODO: Should this +1 to be inclusive?
		self.pending[y1:y2, x1:x2] = colour


	def clear(self):
		self.canvas[:] = 0
		self.pending[:] = self.NO_CHANGE
		self.sender(ansi_clear())


	def close(self):
		self.sender(ansi_reset_colour() + ansi_clear() + ansi_move_cursor(0,0))


	def refresh(self):
		# Find if there are any changes needing to be made
		diff_top = (self.pending[0::2] != self.NO_CHANGE) * (self.canvas[0::2] - self.pending[0::2])
		diff_bot = (self.pending[1::2] != self.NO_CHANGE) * (self.canvas[1::2] - self.pending[1::2])
		diff = (diff_top << 24) + diff_bot # Store top pixel colour in upper bytes

		if np.sum(diff) == 0:
			# No updates required
			return

		data = ""
		last_row = None
		last_col = None
		last_colours = None

		# Get only characters that need to be updated, and the locations
		#  of those changes
		for row, col in zip(*np.where(diff != 0)):
			upper_colour = self.pending[2*row, col]
			if upper_colour == self.NO_CHANGE:
				upper_colour = self.canvas[2*row, col]

			lower_colour = self.pending[2*row+1, col]
			if lower_colour == self.NO_CHANGE:
				lower_colour = self.canvas[2*row+1, col]

			colours = (upper_colour, lower_colour)


			# If we are in the same row, the next column, and same colours
			if row == last_row and col-1 == last_col and colours == last_colours:
				# We can just continue on from the last pixel as it's the same
				data += self.px

			# If we are in the same row, the next column, but different colours
			elif row == last_row and col-1 == last_col:
				# Need to set the new colours and then print the pixel
				data += ansi_set_full_colour(*colours) + self.px

			# If we have skipped any columns or rows, but kept the colours
			elif colours == last_colours:
				# We must move the cursor and draw the pixel
				data += ansi_move_cursor(col, row) + self.px

			# If we have skipped any columns or rows and a new colour
			else:
				# We must move the cursor, update colours, and then draw pixel
				data += ansi_move_cursor(col, row) + ansi_set_full_colour(*colours) + self.px

			# Update the last_ variables
			last_row = row
			last_col = col
			last_colours = colours

		# Update the canvas and reset the pending
		self.canvas[0::2][diff_top != 0] = self.pending[0::2][diff_top != 0]
		self.canvas[1::2][diff_bot != 0] = self.pending[1::2][diff_bot != 0]
		self.pending[:] = self.NO_CHANGE

		# Send off the changes to client's screen
		self.sender(data)



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


