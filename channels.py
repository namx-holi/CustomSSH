
import queue
import threading
from itertools import count, filterfalse

from data_types import DataReader
from messages import (
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
	SSH_MSG_CHANNEL_OPEN_FAILURE,
	SSH_MSG_CHANNEL_SUCCESS,
	SSH_MSG_CHANNEL_FAILURE,
	SSH_MSG_CHANNEL_DATA,
	SSH_MSG_CHANNEL_EOF,
	SSH_MSG_CHANNEL_CLOSE)



class ChannelHandler:
	# Max channels per client. If none, no limit.
	CLIENT_CHANNELS_MAX = 1

	# Max channels per server. If none, no limit.
	SERVER_CHANNELS_MAX = 1
	SERVER_CHANNELS_COUNT = 0

	# TODO: Find a way to set the server-side values for these
	INITIAL_WINDOW_SIZE = 1048576
	MAXIMUM_PACKET_SIZE = 16384


	def __init__(self):
		# Lookup of recipient channels running for the current client.
		self.channels = {}


	def add_channel(self, channel):
		# Retrieve the next lowest server channel between 0 and
		#  CLIENT_CHANNELS_MAX that isn't already used. This is
		#  guaranteed to succeed as before this is called we have
		#  already checked that the current count of clients is already
		#  lower than the max.
		channel_id = next(filterfalse(self.channels.keys().__contains__, count(0)))

		# Store the channel in the client channel dict, and increment
		#  the global SERVER_CHANNELS_COUNT
		self.channels[channel_id] = channel
		self.SERVER_CHANNELS_COUNT += 1

		return channel_id


	# TODO: Method to delete channels once they're closed
	...


	def handle_CHANNEL_OPEN(self, msg, client_running, message_handler):
		# If we have already hit the server max of channels, return a
		#  resource shortage message
		if self.SERVER_CHANNELS_COUNT >= self.SERVER_CHANNELS_MAX:
			return SSH_MSG_CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE(msg.sender_channel)

		# If we have already hit the client max of channels, return a
		#  resource shortage message
		if len(self.channels) >= self.CLIENT_CHANNELS_MAX:
			return SSH_MSG_CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE(msg.sender_channel)

		channel_type = msg.channel_type
		client_channel_id = msg.sender_channel
		initial_window_size = msg.initial_window_size
		maximum_packet_size = msg.maximum_packet_size

		# SSH-CONNECT 6.1
		if channel_type == "session":
			# Start a new session channel, and store
			channel = SessionChannel(
				client_handler=self,
				client_channel_id=client_channel_id,
				initial_window_size=initial_window_size,
				maximum_packet_size=maximum_packet_size,
				client_running=client_running,
				message_handler=message_handler)
			server_channel_id = self.add_channel(channel)

			# Return a success response!
			return SSH_MSG_CHANNEL_OPEN_CONFIRMATION(
				recipient_channel=client_channel_id,
				sender_channel=server_channel_id,
				initial_window_size=self.INITIAL_WINDOW_SIZE,
				maximum_packet_size=self.MAXIMUM_PACKET_SIZE)

		# SSH-CONNECT 7.2.
		elif channel_type == "x11":
			# Don't handle x11. This is hard!
			error_msg = f"Channel type 'x11' not implemented"
			print(f" [*] {error_msg}")
			return SSH_MSG_CHANNEL_OPEN_FAILURE.SSH_OPEN_CONNECT_FAILED(client_channel_id, error_msg)

		# SSH-CONNECT 7.2.
		elif channel_type == "forwarded-tcpip":
			# Don't handle forwarded-tcpip. This is hard!
			error_msg = f"Channel type 'forwarded-tcpip' not implemented"
			print(f" [*] {error_msg}")
			return SSH_MSG_CHANNEL_OPEN_FAILURE.SSH_OPEN_CONNECT_FAILED(client_channel_id, error_msg)

		# SSH-CONNECT 7.2.
		elif channel_type == "direct-tcpip":
			# Don't handle direct-tcpip. This is hard!
			error_msg = "Channel type 'direct-tcpip' not implemented"
			print(f" [*] {error_msg}")
			return SSH_MSG_CHANNEL_OPEN_FAILURE.SSH_OPEN_CONNECT_FAILED(client_channel_id, error_msg)

		# Unhandled channel type
		else:
			error_msg = f"Unknown channel type '{channel_type}'"
			print(f" [*] {error_msg}")
			return SSH_MSG_CHANNEL_OPEN_FAILURE.CONNECT_FAILED(client_channel_id, error_msg)


	def handle_CHANNEL_REQUEST(self, msg):
		# Get the channel. If there is no existing channel for the
		#  given recipient channel, then don't return anything
		channel = self.channels.get(msg.recipient_channel)
		if channel is None:
			return None

		# Handle the request with the actual channel
		resp = channel.handle_CHANNEL_REQUEST(msg)

		# Only return a response if the client asked for one!
		if msg.want_reply:
			return resp
		return None


	def handle_CHANNEL_DATA(self, msg):
		# Get the channel. If there is no existing channel for the
		#  given recipient channel, then end here
		channel = self.channels.get(msg.recipient_channel)
		if channel is None:
			return

		# Pass the request on to the channel to pass to it's app
		channel.data_in(msg.data)


	def handle_CHANNEL_CLOSE(self, msg):
		# Get the channel. If there is no existing channel for the
		#  given recipient channel, then end here
		channel = self.channels.get(msg.recipient_channel)
		if channel is None:
			return

		# Pass the request on to the channel to handle
		channel.handle_CHANNEL_CLOSE()

		# Get rid of references to the channel
		del self.channels[msg.recipient_channel]

		import gc
		gc.collect()
		print("Referrers are: ", gc.get_referrers(channel))
		# TODO: Replace threading with asyncio ? Makes more sense


# SSH-CONNECT 6.1
class SessionChannel:
	
	def __init__(self,
		client_handler,
		client_channel_id,
		initial_window_size,
		maximum_packet_size,
		client_running,
		message_handler
	):
		self.client_handler = client_handler
		self.client_channel_id = client_channel_id
		self.initial_window_size = initial_window_size
		self.maximum_packet_size = maximum_packet_size

		# Client connection running loop is passed so that we can close
		#  the connection with client if the app exits
		self.client_running = client_running

		# Message handler passed from the client. This is done so that
		#  data can be sent to the client asynchronously
		self.message_handler = message_handler

		# An empty pty config. This contains any special characters
		#  or input/output config
		self.config = PseudoTerminalConfig()

		# Flag for if the app is running, and the queue used to push
		#  data to the app running in a thread
		self.app_has_been_started = False
		self.app_running = threading.Event()
		self.app_data_queue = queue.Queue()
		self.app = None

		# If we have sent our own CHANNEL_CLOSE already
		self.client_channel_close_sent = False
		self.server_channel_close_sent = False


	def data_in(self, data):
		# Sends data to the app thread via data queue
		self.app_data_queue.put(data)


	def data_out(self, data):
		# Sends data to the client
		msg = SSH_MSG_CHANNEL_DATA(self.client_channel_id, data)
		self.message_handler.send(msg)


	def start_shell(self):
		# Start a thread that sends "Hi!" every couple seconds to the
		#  client to demonstrate async sending
		self.app_has_been_started = True
		self.app = TestShell(self)
		self.app.start()


	def close_channel(self):
		# If an app is running, terminate that
		print("CHANNEL CLOSING ")
		self.app_running.clear()
		if self.app:
			for thread in self.app.threads:
				thread.join()


	# Sends our own close channel
	def send_close_channel(self):
		# SSH-CONNECT 5.3.

		# Send a channel close
		msg = SSH_MSG_CHANNEL_CLOSE(self.client_channel_id)
		self.message_handler.send(msg)
		self.server_channel_close_sent = True

		# If we have received AND sent a CHANNEL_CLOSE, terminate app
		if self.client_channel_close_sent and self.server_channel_close_sent:
			self.close_channel()


	# Receives client's close channel
	def handle_CHANNEL_CLOSE(self):
		# SSH-CONNECT 5.3.
		self.client_channel_close_sent = True

		# Send our own close channel if not sent already. If already
		#  sent, then we terminate app
		if not self.server_channel_close_sent:
			self.send_close_channel()
		else:
			self.close_channel()


	def handle_CHANNEL_REQUEST(self, msg):
		request_type = msg.request_type

		# SSH-CONNECT 6.2.
		if request_type == "pty-req":
			# Handle the terminal width/height
			success1 = self.config.set_window_size(
				w=msg.term_width,
				h=msg.term_height,
				wpx=msg.term_width_pixels,
				hpx=msg.term_height_pixels)

			# Handle terminal modes
			success2 = self.config.set_terminal_modes(msg.terminal_modes)

			# If either the window size or terminal modes could not be
			#  set, then we need to reset the config and return a fail
			if not success1 or not success2:
				self.config = PseudoTerminalConfig()
				return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)

			# Set the term environment variable and return a success!
			self.config.set_environment_variable("TERM", msg.term_environment_var)
			return SSH_MSG_CHANNEL_SUCCESS(self.client_channel_id)

		# SSH-CONNECT 6.3.1.
		elif request_type == "x11-req":
			# This type of session cannot handle x11 requests
			return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)

		# SSH-CONNECT 6.4.
		elif request_type == "env":
			# Set the environment variable
			self.config.set_environment_variable(msg.name, msg.value)
			return SSH_MSG_CHANNEL_SUCCESS(self.client_channel_id)

		# SSH-CONNECT 6.5.
		elif request_type == "shell":
			# This message will request that the user's default shell
			#  (typically defined in /etc/passwd in UNIX systems) be
			#  started.
			if self.app_has_been_started:
				return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)
			self.start_shell()
			return SSH_MSG_CHANNEL_SUCCESS(self.client_channel_id)

		# SSH-CONNECT 6.5.
		elif request_type == "exec":
			# This message will request that the server start the
			#  execution of the given command. The 'command' string may
			#  contain a path. Normal precautions MUST be taken to
			#  prevent the execution of unauthorized commands.
			
			# We don't handle this currently
			print(" [!] Client requested exec requet_type")
			return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)

		# SSH-CONNECT 6.5.
		elif request_type == "subsystem":
			# This last form executes a predefined subsystem. It is
			#  expected that these will include a general file transfer
			#  mechanism, and possibly other features. Implementations
			#  may also allow configuring more such mechanisms. As the
			#  user's shell is usually used to execute the subsystem, it
			#  is advisable for the subsystem protocol to have a "magic
			#  cookie" at the beginning of the protocol transaction to
			#  distinguish it from arbitrary output generated by shell
			#  initialization scripts, etc. This spurious output from
			#  the shell may be filtered out either at the server or at
			#  the client.

			# We don't handle this currently
			print(" [!] Client requested subsystem request_type")
			return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)

		# SSH-CONNECT 6.7.
		elif request_type == "window-change":
			# Reconfigure the window size
			success = self.config.set_window_size(
				w=msg.term_width,
				h=msg.term_height,
				wpx=msg.term_width_pixels,
				hpx=msg.term_height_pixels)
			if not success:
				return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)
			return SSH_MSG_CHANNEL_SUCCESS(self.client_channel_id)

		# SSH-CONNECT 6.8.
		elif request_type == "xon-xoff":
			# We don't handle this currently
			print(" [!] Client requested xon-xoff request_type")
			return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)

		# SSH-CONNECT 6.9.
		elif request_type == "signal":
			# We don't handle this currently
			print(" [!] Client requested signal request_type")
			return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)

		# SSH-CONNECT 6.10.
		elif request_type == "exit-status":
			# We don't handle this currently
			print(" [!] Client requested exit-status request_type")
			return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)

		# SSH-CONNECT 6.11.
		elif request_type == "exit-signal":
			# We don't handle this currently
			print(" [!] Client requested exit-signal request_type")
			return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)

		# Unhandled request type
		else:
			return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)



class PseudoTerminalConfig:

	def __init__(self):
		# Environment variables
		self.environ = {}

		# Window sizes
		self.window_using_pixels = False
		self.window_width = None
		self.window_height = None
		self.window_width_pixels = None
		self.window_height_pixels = None

		##################
		# TERMINAL MODES #
		##################
		# Special characters
		# https://linuxcommand.org/lc3_man_pages/stty1.html
		# https://www.ibm.com/docs/en/aix/7.1?topic=s-stty-command
		self.discard = None # will toggle discarding of output
		self.eof = None     # will send an end of file (terminate the input)
		self.eol = None     # will end the line
		self.eol2 = None    # alternate for ending the line
		self.erase = None   # will erase the last character typed
		self.intr = None    # will send an interrupt signal
		self.kill = None    # will erase the current line
		self.lnext = None   # will enter the next character quoted
		self.quit = None    # will send a quit signal
		self.rprnt = None   # will redraw the current line
		self.start = None   # will restart the output after stopping it
		self.stop = None    # will stop the output
		self.susp = None    # will send a terminal stop signal
		self.susp2 = None   # alternate for sending a termainl stop signal
		self.swtch = None   # will switch to a different shell layer
		self.werase = None  # will erase the last word typed

		# Special settings
		self.ispeed = None # the input speed, baud rate
		self.ospeed = None # the output speed, baud rate


	def set_terminal_modes(self, blob) -> bool: # returns success bool
		# If the terminal mode string is empty, then ignored.
		if blob == b"":
			return True

		# Store any unhandled op codes to print a warning notification
		unhandled_opcodes = []

		# SSH-CONNECT 8. Encoding of Terminal Modes
		r = DataReader(blob)
		while True:
			opcode = r.read_uint8()

			# Indicates end of options
			if opcode == 0: break # TTY_OP_END

			# Special characters
			elif opcode == 5: self.eof = r.read_uint32() # VEOF
			elif opcode == 6: self.eol = r.read_uint32() # VEOL
			elif opcode == 7: self.eol2 = r.read_uint32() # VEOL2
			elif opcode == 3: self.erase = r.read_uint32() # VERASE
			elif opcode == 1: self.intr = r.read_uint32() # VINTR
			elif opcode == 4: self.kill = r.read_uint32() # VKILL
			elif opcode == 14: self.lnext = r.read_uint32() # VLNEXT
			elif opcode == 2: self.quit = r.read_uint32() # VQUIT
			elif opcode == 12: self.rprnt = r.read_uint32() # VREPRINT
			elif opcode == 8: self.start = r.read_uint32() # VSTART
			elif opcode == 9: self.stop = r.read_uint32() # VSTOP
			elif opcode == 10: self.susp = r.read_uint32() # VSUSP
			elif opcode == 11: self.susp2 = r.read_uint32()# VDSUSP
			elif opcode == 16: self.swtch = r.read_uint32() # VSWTCH
			elif opcode == 13: self.werase = r.read_uint32() # VWERASE
			# elif opcode == 15: # VFLUSH
			# elif opcode == 17: # VSTATUS
			# elif opcode == 18: # VDISCARD
			
			# Special settings
			elif opcode == 128: self.ispeed = r.read_uint32() # 128
			elif opcode == 129: self.ospeed = r.read_uint32() # 129

			# Unhandled op code
			else:
				unhandled_opcodes.append(opcode)
				_ = r.read_uint32()

		if unhandled_opcodes:
			print(" [!] Unhandled opcodes:", unhandled_opcodes)

		return True


	def set_window_size(self, w, h, wpx, hpx) -> bool: # returns success bool
		# Character/row dimensions override the pixel dimensions when
		#  non-zero
		if w != 0 and h != 0:
			self.window_using_pixels = False
			self.window_width = w
			self.window_height = h
			self.window_width_pixels = None
			self.window_height_pixels = None
			return True
		elif wpx != 0 and hpx != 0:
			self.window_using_pixels = True
			self.window_width = None
			self.window_height = None
			self.window_width_pixels = wpx
			self.window_height_pixels = hpx
			return True
		else:
			# Invalid combo of window size values
			return False


	def set_environment_variable(self, name, value):
		self.environ[name] = value



# A test shell application
import time
class TestShell:
	"""
	Test shell. Sends the letter A to the client every 2 seconds. If it
	a letter from the user, starts sending that letter instead.
	"""

	def __init__(self, session):
		self.session = session
		self.running = session.app_running
		self.data_queue = session.app_data_queue
		self.config = session.config

		# Threads used by this app
		self.threads = []

		# Data used by this app
		self.word = b""


	def start(self):
		self.running.set()

		print_loop_t = threading.Thread(target=self.print_loop)
		input_loop_t = threading.Thread(target=self.input_loop)
		
		# print_loop_t.daemon = True
		# input_loop_t.daemon = True

		print_loop_t.start()
		input_loop_t.start()

		self.threads = [print_loop_t, input_loop_t]


	def stop(self):
		print("STOPPING APP")
		self.running.clear()
		self.session.send_close_channel()


	def input_loop(self):
		input_buffer = b""

		while self.running.isSet():
			# Read next pending user input
			try:
				print("Trying to read from queue")
				input_buffer += self.data_queue.get(timeout=1)
			except queue.Empty:
				continue

			# If we have received any ^C, we must exit
			if bytes([self.config.eof]) in input_buffer:
				self.stop()
				break

			# If we received a new line, handle the buffer and reset the
			#  buffer
			if b"\r" in input_buffer:
				self.word, _, input_buffer = input_buffer.partition(b"\n")
				self.word += b"\r\n"

		print("End of input thread")


	def print_loop(self):
		# Let user know what they can do
		self.session.data_out("Type something and press enter. This will be echoed every second.\r\n")
		self.session.data_out("CTRL+D will exit.\r\n")

		while self.running.isSet():
			self.session.data_out(self.word)
			time.sleep(1)

		print("End of print thread")



if __name__ == "__main__":
	terminal_modes = b'\x81\x00\x00\x96\x00\x80\x00\x00\x96\x00\x01\x00\x00\x00\x03\x02\x00\x00\x00\x1c\x03\x00\x00\x00\x7f\x04\x00\x00\x00\x15\x05\x00\x00\x00\x04\x06\x00\x00\x00\xff\x07\x00\x00\x00\xff\x08\x00\x00\x00\x11\t\x00\x00\x00\x13\n\x00\x00\x00\x1a\x0c\x00\x00\x00\x12\r\x00\x00\x00\x17\x0e\x00\x00\x00\x16\x12\x00\x00\x00\x0f\x1e\x00\x00\x00\x00\x1f\x00\x00\x00\x00 \x00\x00\x00\x00!\x00\x00\x00\x00"\x00\x00\x00\x00#\x00\x00\x00\x00$\x00\x00\x00\x01%\x00\x00\x00\x00&\x00\x00\x00\x01\'\x00\x00\x00\x01(\x00\x00\x00\x00)\x00\x00\x00\x01*\x00\x00\x00\x012\x00\x00\x00\x013\x00\x00\x00\x014\x00\x00\x00\x005\x00\x00\x00\x016\x00\x00\x00\x017\x00\x00\x00\x018\x00\x00\x00\x009\x00\x00\x00\x00:\x00\x00\x00\x00;\x00\x00\x00\x01<\x00\x00\x00\x01=\x00\x00\x00\x01>\x00\x00\x00\x00F\x00\x00\x00\x01G\x00\x00\x00\x00H\x00\x00\x00\x01I\x00\x00\x00\x00J\x00\x00\x00\x00K\x00\x00\x00\x00Z\x00\x00\x00\x01[\x00\x00\x00\x01\\\x00\x00\x00\x00]\x00\x00\x00\x00\x00'

	tc = TerminalConfig()
	tc.set_terminal_modes(terminal_modes)
