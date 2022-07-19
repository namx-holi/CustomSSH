
import queue
import threading

from apps.generic import AppGeneric


# A basic chat
class BasicChatApp(AppGeneric):

	# Global dict of currently running session queues. When a user sends
	#  a message, that message is added to each of these queues so it
	#  can be printed on each user's screen.
	RUNNING_SESSION_QUEUES = {}


	def __init__(self, session):
		self.session = session

		# Key bindings
		self.eof_char = None
		self.erase_char = None
		self.intr_char = None
		self.in_NL = None
		self.out_NL = None
		self.setup_keybinds(session.config)

		# Data used by this app
		self.running = threading.Event()
		self.input_data = queue.Queue() # Keypresses from the user
		self.incoming_messages = None # Queue for any messages to print
		self.user_input_buffer = b"" # Keeps track of what the user has typed
		self.username = b"USER" # Name of user

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

		# Read the client's [Backspace] character from config if available
		if config.erase not in [None, 255]: # Set to something valid
			self.erase_char = bytes([config.erase])
		elif config.erase == 255: # Explicitly set as nothing
			self.erase_char = None
		else: # Default value
			self.erase_char = None

		# Read the client's [CTRL+C] character from config if available
		if config.intr not in [None, 255]: # Set to something valid
			self.intr_char = bytes([config.intr])
		elif config.intr == 255: # Explicitly set as nothing
			self.intr_char = None
		else: # Default value
			self.intr_char = None

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
			threading.Thread(target=self.chat_loop)
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

		# Unregister the queue
		del BasicChatApp.RUNNING_SESSION_QUEUES[self]


	def handle_CHANNEL_DATA(self, msg):
		# Add incoming data to the input data queue to pass to running
		#  thread
		self.input_data.put(msg.data)


	def chat_loop(self):
		# Send our initial messages
		self.send_CHANNEL_DATA(b"Hi! Use CTRL+D to exit" + self.out_NL)
		self.read_username()

		# Set up a message queue and register it
		self.incoming_messages = queue.Queue()
		BasicChatApp.RUNNING_SESSION_QUEUES[self] = self.incoming_messages

		while self.running.isSet():
			# Handle user input (blocks for short time)
			self.handle_user_input()

			# And handle any pending messages to print
			self.print_new_messages()


	def read_username(self):
		username_buffer = b""

		self.send_CHANNEL_DATA(b"Enter username" + self.out_NL)
		self.send_CHANNEL_DATA(b"> ")
		while True:
			# Read next pending user input
			try:
				user_input = self.input_data.get(timeout=0.1)
			except queue.Empty:
				# If no user input, no need to do anything
				continue

			# If we have received any ^D, we must exit
			if self.eof_char is not None and self.eof_char in user_input:
				self.send_CHANNEL_DATA(self.out_NL + b"Goodbye!")
				self.send_CHANNEL_CLOSE()
				self.running.clear()
				return

			# Add new input to the buffer
			username_buffer += user_input

			# If we have received a backspace, remove the character before
			#  that backspace
			if self.erase_char is not None and self.erase_char in user_input:
				before_erase, _, after_erase = username_buffer.partition(self.erase_char)

				# Clear the typing line
				overwrite_line = b"\r" + b" "*(2 + len(username_buffer)) + b"\r" # +2 for '> '
				self.send_CHANNEL_DATA(overwrite_line)

				# Update the buffer and reprint that
				username_buffer = before_erase[0:-1] + after_erase
				new_typing_line = b"> " + username_buffer
				self.send_CHANNEL_DATA(new_typing_line)

			# If we have received a new line, send the message off to other
			#  clients, and print a new typing line
			elif self.in_NL in user_input:
				# Hello, World!\nHi! -> msg="Hello, World" and buffer="Hi!"
				username, _, new_username_buffer = username_buffer.partition(self.in_NL)

				# If not empty, set username, announce user, and exit loop
				if len(username) > 0:
					self.username = username

					self.send_CHANNEL_DATA(self.out_NL*2 + b"Welcome, " + self.username + b"!" + self.out_NL + b"> ")
					for q in BasicChatApp.RUNNING_SESSION_QUEUES.values():
						q.put([b"User '" + username + b"' has joined."])
					return

				else:
					# "> Hello, World!" overwritten to "> "
					overwrite_line = b"\r" + b" "*(2 + len(username_buffer)) + b"\r" # +2 for '> '
					self.send_CHANNEL_DATA(overwrite_line)
					self.send_CHANNEL_DATA(b"> " + new_username_buffer)

					# Update the username buffer
					username_buffer = new_username_buffer

			else:
				# Print the new input to the existing typing line
				# "> ..." -> "> ...Hello, World!"
				self.send_CHANNEL_DATA(user_input)


	def handle_user_input(self):
		# Read next pending user input
		try:
			user_input = self.input_data.get(timeout=0.1)
		except queue.Empty:
			# If no user input, no need to do anything
			return

		# If we have received any ^D, we must exit
		if self.eof_char is not None and self.eof_char in user_input:
			for q in BasicChatApp.RUNNING_SESSION_QUEUES.values():
				q.put([b"User '" + self.username + b"' has disconnected."])
			self.send_CHANNEL_DATA(self.out_NL + b"Goodbye!" + self.out_NL)
			self.send_CHANNEL_CLOSE()
			self.running.clear()
			return

		# Add new input to the buffer
		self.user_input_buffer += user_input
		
		# If we have received a backspace, remove the character before
		#  that backspace
		if self.erase_char is not None and self.erase_char in user_input:
			before_erase, _, after_erase = self.user_input_buffer.partition(self.erase_char)

			# Clear the typing line
			overwrite_line = b"\r" + b" "*(2 + len(self.user_input_buffer)) + b"\r" # +2 for '> '
			self.send_CHANNEL_DATA(overwrite_line)

			# Update the buffer and reprint that
			self.user_input_buffer = before_erase[0:-1] + after_erase
			new_typing_line = b"> " + self.user_input_buffer
			self.send_CHANNEL_DATA(new_typing_line)

		# If we have received a new line, send the message off to other
		#  clients, and print a new typing line
		elif self.in_NL in user_input:
			# Hello, World!\nHi! -> msg="Hello, World" and buffer="Hi!"
			msg, _, new_user_input_buffer = self.user_input_buffer.partition(self.in_NL)

			# If not an empty message, add to all message queues to print
			#  on all user's screens
			if len(msg) > 0:
				for q in BasicChatApp.RUNNING_SESSION_QUEUES.values():
					q.put([self.username + b": " + msg])

			# "> Hello, World!" overwritten to "> "
			overwrite_line = b"\r" + b" "*(2 + len(self.user_input_buffer)) + b"\r" # +2 for '> '
			self.send_CHANNEL_DATA(overwrite_line)
			self.send_CHANNEL_DATA(b"> " + new_user_input_buffer)

			# Update the buffer
			self.user_input_buffer = new_user_input_buffer

		else:
			# Print the new input to the existing typing line
			# "> ..." -> "> ...Hello, World!"
			self.send_CHANNEL_DATA(user_input)


	def print_new_messages(self):
		# Pull any and all new messages
		msgs = []
		while True:
			try:
				msgs += self.incoming_messages.get_nowait()
			except queue.Empty:
				break

		# If no messages, end here
		if not msgs:
			return

		# If there were any messages, we need to overwrite the typing
		#  line ('> Hello, World' at the bottom), print the new messages
		#  and then reprint the typing line
		overwrite_line = b"\r" + b" "*(2 + len(self.user_input_buffer)) + b"\r" # +2 for '> '
		self.send_CHANNEL_DATA(overwrite_line)

		for msg in msgs:
			message_line = msg + self.out_NL
			self.send_CHANNEL_DATA(message_line)

		new_typing_line = b"> " + self.user_input_buffer
		self.send_CHANNEL_DATA(new_typing_line)
