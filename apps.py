import queue
import time
import threading

from messages import (SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_CLOSE)


# TODO: Use this as an actual parent class. Currently it's just being
#  used to guide what methods should be generic
class AppGeneric:
	def __init__(self, session):
		self.session = session

		# To write for each app
		pass

	def start(self):
		# To write for each app
		pass

	def stop(self):
		# To write for each app
		pass

	def handle_CHANNEL_DATA(self, msg):
		# To write for each app
		pass

	def send_CHANNEL_DATA(self, data):
		self.session.send_CHANNEL_DATA(data)

	def send_CHANNEL_CLOSE(self):
		self.session.send_CHANNEL_CLOSE()



# A test shell application
class TestShell(AppGeneric): # Requires a SessionChannel. TODO: Check for this.
	
	def __init__(self, session):
		self.session = session
		
		# Read the client's [CTRL+D] character from config if available
		if session.config.eof not in [None, 255]: # Set to something valid
			self.eof_char = bytes([session.config.eof])
		elif session.config.eof == 255: # Explicitly set as nothing
			self.eof_char = None
		else: # Default value
			self.eof_char = None

		# Read the client's [Backspace] character from config if available
		if session.config.erase not in [None, 255]: # Set to something valid
			self.erase_char = bytes([session.config.erase])
		elif session.config.erase == 255: # Explicitly set as nothing
			self.erase_char = None
		else: # Default value
			self.erase_char = None

		# Read the client's [CTRL+C] character from config if available
		if session.config.intr not in [None, 255]: # Set to something valid
			self.intr_char = bytes([session.config.intr])
		elif session.config.intr == 255: # Explicitly set as nothing
			self.intr_char = None
		else: # Default value
			self.intr_char = None

		# Handling NL and CR
		if session.config.icrnl:
			self.in_NL = b"\r"
		else:
			self.in_NL = b"\n"

		if session.config.onlcr:
			self.out_NL = b"\r\n"
		else:
			self.out_NL = b"\n"


		print("Input: NL->CR =", session.config.inlcr)
		print("Input: Ignore CR =", session.config.igncr)
		print("Input: CR->NL =", session.config.icrnl)
		print("Output: NL->CRNL =", session.config.onlcr)
		print("Output: Translate CR->NL =", session.config.ocrnl)
		print("Output: Translate NL->CRNL =", session.config.onocr)
		print("Output: NL performs CR =", session.config.onlret)

		# Data used by this app
		self.running = threading.Event()
		self.data_queue = queue.Queue()
		self.word = b""

		# Threads used by this app
		self.threads = []


	def start(self):
		"""
		Start all relevant threads
		"""
		self.running.set()

		print_loop_t = threading.Thread(target=self.print_loop)
		input_loop_t = threading.Thread(target=self.input_loop)
		self.threads = [print_loop_t, input_loop_t]

		# Set threads as daemon
		for t in self.threads:
			t.daemon = True

		# Start threads
		for t in self.threads:
			t.start()


	def stop(self):
		"""
		Stop all relevant threads
		"""
		self.running.clear()

		for t in self.threads:
			t.join()


	def handle_CHANNEL_DATA(self, msg):
		self.data_queue.put(msg.data)


	def input_loop(self):
		input_buffer = b""

		while self.running.isSet():
			# Read next pending user input
			try:
				input_buffer += self.data_queue.get(timeout=1)
			except queue.Empty:
				continue

			print("INPUT_BUFFER =", input_buffer)

			# If we have received any ^D, we must exit
			if self.eof_char is not None and self.eof_char in input_buffer:
				self.send_CHANNEL_CLOSE()
				self.running.clear()
				break

			# If we received a new line, handle the buffer correctly
			if self.in_NL in input_buffer:
				self.word, _, input_buffer = input_buffer.partition(self.in_NL)
				self.word += self.out_NL


	def print_loop(self):
		# Let user know what they can do
		self.send_CHANNEL_DATA("Type something and press ENTER. This will be echoed every second.\r\n")
		self.send_CHANNEL_DATA("CTRL+D will exit.\r\n")

		while self.running.isSet():
			if self.word != b"":
				self.send_CHANNEL_DATA(self.word)
				time.sleep(1)
