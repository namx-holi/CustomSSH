
import cv2
import numpy as np
import threading


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





class Batch:
	"""
	An object returned by the Screen class. This object can be used to
	make many edits to the screen without the screen rendering somewhere
	in the middle of these changes. Then all the changes can be sent off
	to the screen at once.
	"""
	def __init__(self, screen):
		self.screen = screen
		self.sent = False # If it has been sent to the screen already.

		# Used to signify no update in pending
		self.NO_CHANGE = -1
		# Pending array
		self.pending = np.empty((screen.height, screen.width), dtype=int)
		self.pending[:] = self.NO_CHANGE

		self.width = self.screen.width
		self.height = self.screen.height


	def draw(self):
		# TODO: Is there a reason why a batch can't be sent to a screen
		#  more than once?
		# if self.sent:
		# 	print("Batch already sent to screen")
		# 	return
		# self.sent = True

		# Sends all the updates to the screen
		self.screen.draw_batch(self)


	# TODO: Move these draw methods somewhere else that can be inherited
	def draw_pixel(self, x, y, colour, under=False):
		# Don't draw if out of screen range
		if x < 0 or x >= self.width:
			return
		if y < 0 or y >= self.height:
			return

		# If drawing pixel under, only fill if the pixel has not already
		#  been set
		if under and self.pending[y,x] == self.NO_CHANGE:
			return

		# Sets one pixel in the pending view
		self.pending[y,x] = colour


	def draw_line(self, x1, x2, y1, y2, colour):
		"""Bresenham's line algorithm from rosetta code"""
		dx = abs(x2 - x1)
		dy = abs(y2 - y1)

		# TODO: If there is no gradient, just draw boxes, much quicker
		if dx == 0 or dy == 0:
			self.draw_box(x1, x2, y1, y2, colour, fill=True)
			# self.draw_pixel(x2, y2, colour)
			return

		x, y = x1, y1
		sx = -1 if x1 > x2 else 1
		sy = -1 if y1 > y2 else 1
		if dx > dy:
			err = dx / 2.0
			while x != x2:
				self.draw_pixel(x, y, colour)
				err -= dy
				if err < 0:
					y += sy
					err += dx
				x += sx
		else:
			err = dy / 2.0
			while y != y2:
				self.draw_pixel(x, y, colour)
				err -= dx
				if err < 0:
					x += sx
					err += dy
				y += sy
		self.draw_pixel(x, y, colour)


	def draw_box(self, x1, x2, y1, y2, colour, fill=False, under=False):
		# Draws a filled box from (x1,y1) to (x2,y2) in a colour

		# If just a single pixel
		if x1 == x2 and y1 == y2:
			self.draw_pixel(x1, y1, colour, under=under)

		# Swapping coords if we need to to draw from top left to bot right
		if x1 > x2:
			x1, x2 = x2, x1
		if y1 > y2:
			y1, y2 = y2, y1

		# Box is inclusive of coords. TODO: Verify this?
		# x2 += 1
		# y2 += 1

		# If any x or y coords are the same, indexing [x:x] won't give
		#  anything, so we need to address slightly differently
		if x1 == x2 and y1 == y2:
			self.draw_pixel(x1, y1, colour, under=under)
		elif x1 == x2:
			draw_region = self.pending[y1:y2+1,x1:x1+1]
			if under:
				draw_region[draw_region == self.NO_CHANGE] = colour
			else:
				draw_region[:] = colour
			# self.pending[y1:y2+1,x1:x1+1] = colour # Vertical line

		elif y1 == y2:
			draw_region = self.pending[y1:y1+1,x1:x2+1]
			if under:
				draw_region[draw_region == self.NO_CHANGE] = colour
			else:
				draw_region[:] = colour
			# self.pending[y1:y1+1,x1:x2+1] = colour # Horizontal line

		elif fill:
			draw_region = self.pending[y1:y2+1, x1:x2+1]
			if under:
				draw_region[draw_region == self.NO_CHANGE] = colour
			else:
				draw_region[:] = colour
			# self.pending[y1:y2, x1:x2] = colour # Actual box

		else:
			# Draw 4 boxes, one for each border
			draw_region = self.pending[y1:y2+1, x1:x2+1]
			center_space = draw_region[1:-1, 1:-1].copy()

			if under:
				draw_region[draw_region == self.NO_CHANGE] = colour
			else:
				draw_region[:] = colour

			# Restore the center space
			draw_region[1:-1, 1:-1] = center_space

			# # Draw 4 boxes, one for each border
			# # TODO: Speed this up possibly?
			# self.pending[y1:y1+1, x1:x2] = colour # Top
			# self.pending[y2-1:y2, x1:x2] = colour # Bottom
			# self.pending[y1:y2, x1:x1+1] = colour # Left
			# self.pending[y1:y2, x2-1:x2] = colour # Right


	def draw_image(self, x, y, filename):
		# Loads an image and draws it to canvas with top left corner at
		#  the given coordinate
		img = cv2.imread(filename, cv2.IMREAD_UNCHANGED) # unchanged for alpha channel
		height, width, _ = img.shape

		# Combine the RGB channels into one hex number
		pixels = img[:,:,2]*0x10000 + img[:,:,1]*0x100 + img[:,:,0]

		# Extract only non transparent pixels
		visible = img[:,:,3] > 0

		# Calculate overlap of the image with the screen borders
		l_overlap = -min(0, x)
		r_overlap = max(0, x + width - self.width)
		t_overlap = -min(0, y)
		b_overlap = max(0, y + height - self.height)

		# Calculate the region of screen space that is going to be drawn
		#  to, and the region of the image that is to be drawn
		img_x1 = l_overlap # Start from what doesn't left overlap
		img_x2 = width - r_overlap # Cut off right overlap
		img_y1 = t_overlap # Start from what doesn't top overlap
		img_y2 = height - b_overlap # Cut off bottom overlap
		scr_x1 = x + l_overlap # Cut off printing space by overlap
		scr_x2 = x + width - r_overlap # Cut off printing space by overlap
		scr_y1 = y + t_overlap # Cut off printing space by overlap
		scr_y2 = y + height - b_overlap # Cut off printing space by overlap

		# Extract the visible pixels from what's actually going to be displayed
		visible = img[img_y1:img_y2,img_x1:img_x2,3] > 0

		# Draw the visible pixels to canvas
		# self.pending[scr_y1:scr_y2,scr_x1:scr_x2] = pixels[img_y1:img_y2,img_x1:img_x2]
		self.pending[scr_y1:scr_y2,scr_x1:scr_x2][visible] = pixels[img_y1:img_y2,img_x1:img_x2][visible]



class Screen:
	# Handles updating pixels only when needed. Uses block elements to
	#  draw two pixels per character

	def __init__(self, height, width, sender):
		# The char will be used for upper half, and bg for lower half
		self.px = "▀"

		# Used to signify no update in pending
		self.NO_CHANGE = -1

		self.width  = np.clip(width, 0, 320)
		self.height = np.clip(height*2, 0, 200)
		print(f"Created screen of size ({self.width}x{self.height})")

		self.canvas  = np.zeros((self.height, self.width), dtype=int)
		self.pending = np.empty((self.height, self.width), dtype=int)

		self.pending[:] = self.NO_CHANGE

		# Prevents writing to the pending table if already writing to
		self.pending_lock = threading.Lock()
		self.batch_lock = threading.Lock()

		# Data will be sent to the client by calling this sender
		self.sender = sender

		# Clear the screen to start off, then fill it with black.
		self.clear()
		self.draw_box(0,self.width,0,self.height, 0x333333, fill=True)
		self.refresh()


	def new_batch(self):
		# Returns an object that can be drawn to, to then be sent to
		#  the screen all at once
		return Batch(self)


	def draw_batch(self, batch):
		self.pending_lock.acquire()
		self.pending[batch.pending != batch.NO_CHANGE] = batch.pending[batch.pending != batch.NO_CHANGE]
		self.pending_lock.release()


	def draw_pixel(self, x, y, colour):
		batch = self.new_batch()
		batch.draw_pixel(x, y, colour)
		batch.draw()


	def draw_line(self, x1, x2, y1, y2, colour):
		batch = self.new_batch()
		batch.draw_line(x1, x2, y1, y2, colour)
		batch.draw()


	def draw_box(self, x1, x2, y1, y2, colour, fill=False, under=False):
		batch = self.new_batch()
		batch.draw_box(x1, x2, y1, y2, colour, fill, under)
		batch.draw()


	def draw_image(self, x, y, filename):
		batch = self.new_batch()
		batch.draw_image(x, y, filename)
		batch.draw()


	def clear(self):
		self.pending_lock.acquire()
		self.canvas[:] = 0
		self.pending[:] = self.NO_CHANGE
		self.pending_lock.release()
		self.sender(ansi_clear())


	def close(self):
		self.sender(ansi_reset_colour() + ansi_clear() + ansi_move_cursor(0,0))


	def refresh(self):
		# Find if there are any changes needing to be made. Also update
		#  the canvas and pending.
		self.pending_lock.acquire()
		diff_top = (self.pending[0::2] != self.NO_CHANGE) * (self.canvas[0::2] - self.pending[0::2])
		diff_bot = (self.pending[1::2] != self.NO_CHANGE) * (self.canvas[1::2] - self.pending[1::2])
		self.canvas[0::2][diff_top != 0] = self.pending[0::2][diff_top != 0]
		self.canvas[1::2][diff_bot != 0] = self.pending[1::2][diff_bot != 0]
		self.pending[:] = self.NO_CHANGE
		self.pending_lock.release()

		diff = (diff_top << 24) + diff_bot # Store top pixel colour in upper bytes

		if np.sum(diff) == 0:
			# No updates required
			return

		data_blocks = []
		data = ""
		last_row = None
		last_col = None
		last_colours = None

		max_packet_length = 4096

		# Get only characters that need to be updated, and the locations
		#  of those changes
		new_data = ""
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
				new_data = self.px

			# If we are in the same row, the next column, but different colours
			elif row == last_row and col-1 == last_col:
				# Need to set the new colours and then print the pixel
				new_data = ansi_set_full_colour(*colours) + self.px

			# If we have skipped any columns or rows, but kept the colours
			elif colours == last_colours:
				# We must move the cursor and draw the pixel
				new_data = ansi_move_cursor(col, row) + self.px

			# If we have skipped any columns or rows and a new colour
			else:
				# We must move the cursor, update colours, and then draw pixel
				new_data = ansi_move_cursor(col, row) + ansi_set_full_colour(*colours) + self.px

			# Add the new data, unless it exceeds the max packet length,
			#  then the existing data is added to the data blocks and
			#  a new data is started
			if len(data) + len(new_data) > max_packet_length:
				data_blocks.append(data)
				data = new_data
			else:
				data += new_data

			# Update the last_ variables
			last_row = row
			last_col = col
			last_colours = colours

		# If there is existing data in new_data, add it to the blocks
		if data:
			data_blocks.append(data)

		# Send off the changes to client's screen
		for d in data_blocks:
			self.sender(d)
