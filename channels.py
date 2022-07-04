
from itertools import count, filterfalse

from apps import TestShell
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


	def close_channel(self, channel_id):
		del self.channels[channel_id]
		print(f" [*] Channel {channel_id} closed.")


	def close_all_channels(self):
		channel_ids = list(self.channels.keys())
		for channel_id in channel_ids:
			channel = self.channels.get(channel_id)
			channel.handle_CHANNEL_CLOSE()
			self.close_channel(channel_id)


	def handle_CHANNEL_OPEN(self, msg, message_handler):
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
		channel.handle_CHANNEL_DATA(msg)


	# TODO: Implement
	def handle_CHANNEL_EXTENDED_DATA(self, msg):
		# Get the channel. If there is no existing channel for the
		#  given recipient channel, then end here
		channel = self.channels.get(msg.recipient_channel)
		if channel is None:
			return

		print("TODO: Implement handle_CHANNEL_EXTENDED_DATA")


	def handle_CHANNEL_CLOSE(self, msg):
		# Get the channel. If there is no existing channel for the
		#  given recipient channel, then end here
		channel = self.channels.get(msg.recipient_channel)
		if channel is None:
			return

		# Close that channel
		channel.handle_CHANNEL_CLOSE()
		self.close_channel(msg.recipient_channel)


	def handle_CHANNEL_EOF(self, msg):
		# Get the channel. If there is no existing channel for the
		#  given recipient channel, then end here
		channel = self.channels.get(msg.recipient_channel)
		if channel is None:
			return

		# Pass on message to channel
		channel.handle_CHANNEL_EOF()
		


# SSH-CONNECT 6.1
class SessionChannel:
	
	def __init__(self,
		client_handler,
		client_channel_id,
		initial_window_size,
		maximum_packet_size,
		message_handler
	):
		self.client_handler = client_handler
		self.client_channel_id = client_channel_id
		self.initial_window_size = initial_window_size
		self.maximum_packet_size = maximum_packet_size

		# Message handler passed from the client. This is done so that
		#  data can be sent to the client asynchronously
		self.message_handler = message_handler

		# An empty pty config. This contains any special characters
		#  or input/output config
		self.config = PseudoTerminalConfig()

		# Our app, and a flag for whether an app has been started before
		#  so we can prevent starting multiple apps on the same channel
		self.app = None
		self.app_has_been_started = False

		# If we have sent our own CHANNEL_CLOSE already
		self.sent_channel_close = False


	def handle_CHANNEL_REQUEST(self, msg):
		request_type = msg.request_type

		# SSH-CONNECT 6.2.
		# NOTE: If user connects using ssh -T ..., pty-req is skipped
		#  and shell is directly called, so config may not be set up.
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
		elif request_type == "x11-req": # Unhandled
			single_connection = msg.single_connection
			auth_protocol = msg.auth_protocol
			auth_cookie = msg.auth_cookie
			screen_number = msg.screen_number

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
			command = msg.command

			# This message will request that the server start the
			#  execution of the given command. The 'command' string may
			#  contain a path. Normal precautions MUST be taken to
			#  prevent the execution of unauthorized commands.
			
			# We don't handle this currently
			print(f" [!] Client requested exec requet_type. Command={command}")
			return SSH_MSG_CHANNEL_FAILURE(self.client_channel_id)

		# SSH-CONNECT 6.5.
		elif request_type == "subsystem": # Unhandled
			subsystem_name = msg.subsystem_name
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

			print(f" [!] Client requested 'subsystem:' Sybsystem name={subsystem_name}")
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


	def start_shell(self):
		# Start a thread that sends "Hi!" every couple seconds to the
		#  client to demonstrate async sending
		self.app_has_been_started = True
		self.app = TestShell(self)
		self.app.start()


	# Passes CHANNEL_DATA down from client handler to app
	def handle_CHANNEL_DATA(self, msg):
		if self.app is not None:
			self.app.handle_CHANNEL_DATA(msg)


	# Passes CHANNEL_DATA up from app to client handler
	# TODO: Have this method call something in parent rather than
	#  directly use the message_handler
	def send_CHANNEL_DATA(self, data):
		msg = SSH_MSG_CHANNEL_DATA(self.client_channel_id, data)
		self.message_handler.send(msg)


	# Receives client's close channel
	def handle_CHANNEL_CLOSE(self):
		# Stop the app.
		if self.app is not None:
			self.app.stop()
			self.app = None

		# If we have not sent our own CHANNEL_CLOSE, then we must
		#  respond with our own. Otherwise we have received a response
		#  to our own CHANNEL_CLOSE and can do nothing.
		if not self.sent_channel_close:
			self.send_CHANNEL_CLOSE()


	# Sends server's close channel
	# TODO: Have this method call something in parent rather than
	#  directly use the message_handler
	def send_CHANNEL_CLOSE(self):
		# NOTE: We don't have to handle any actual channel closing here
		#  as that can be handled either when we receive a response to
		#  this msg, or when the client wishes to close of their own
		#  accord. Also, this will likely be called from a thread which
		#  could cause issues when a thread is requested to join from
		#  within itself.
		msg = SSH_MSG_CHANNEL_CLOSE(self.client_channel_id)
		self.message_handler.send(msg)
		self.sent_channel_close = True


	def handle_CHANNEL_EOF(self):
		# No explicit response is sent to this message. However, we
		#  may send EOF to the client. The channel remains open after
		#  this message, and more data may still be sent in the other
		#  direction. This message does not consume window space and
		#  can be sent even if no window space is available.
		self.send_CHANNEL_EOF()
		self.send_CHANNEL_CLOSE()


	def send_CHANNEL_EOF(self):
		msg = SSH_MSG_CHANNEL_EOF(self.client_channel_id)
		self.message_handler.send(msg)



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

		# Input settings
		self.inlcr = 0 # Map NL into CR on input
		self.igncr = 0 # Ignore CR on input
		self.icrnl = 0 # Map CR to NL on input

		# Output settings
		self.onlcr = 0 # Map NL to CR-NL (output)
		self.ocrnl = 0 # Translate CR to NL (output)
		self.onocr = 0 # Translate NL to CRNL (output)
		self.onlret = 0 # Newline performs a carriage return (output)

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
			
			# Input settings
			elif opcode == 34: self.inlcr = r.read_uint32() # INLCR
			elif opcode == 35: self.igncr = r.read_uint32() # IGNCR
			elif opcode == 36: self.icrnl = r.read_uint32() # ICRNL

			# Output settings
			elif opcode == 72: self.onlcr = r.read_uint32() # ONLCR
			elif opcode == 73: self.ocrnl = r.read_uint32() # ONLCR
			elif opcode == 74: self.onocr = r.read_uint32() # ONOCR
			elif opcode == 75: self.onlret = r.read_uint32() # ONLRET

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



if __name__ == "__main__":
	terminal_modes = b'\x81\x00\x00\x96\x00\x80\x00\x00\x96\x00\x01\x00\x00\x00\x03\x02\x00\x00\x00\x1c\x03\x00\x00\x00\x7f\x04\x00\x00\x00\x15\x05\x00\x00\x00\x04\x06\x00\x00\x00\xff\x07\x00\x00\x00\xff\x08\x00\x00\x00\x11\t\x00\x00\x00\x13\n\x00\x00\x00\x1a\x0c\x00\x00\x00\x12\r\x00\x00\x00\x17\x0e\x00\x00\x00\x16\x12\x00\x00\x00\x0f\x1e\x00\x00\x00\x00\x1f\x00\x00\x00\x00 \x00\x00\x00\x00!\x00\x00\x00\x00"\x00\x00\x00\x00#\x00\x00\x00\x00$\x00\x00\x00\x01%\x00\x00\x00\x00&\x00\x00\x00\x01\'\x00\x00\x00\x01(\x00\x00\x00\x00)\x00\x00\x00\x01*\x00\x00\x00\x012\x00\x00\x00\x013\x00\x00\x00\x014\x00\x00\x00\x005\x00\x00\x00\x016\x00\x00\x00\x017\x00\x00\x00\x018\x00\x00\x00\x009\x00\x00\x00\x00:\x00\x00\x00\x00;\x00\x00\x00\x01<\x00\x00\x00\x01=\x00\x00\x00\x01>\x00\x00\x00\x00F\x00\x00\x00\x01G\x00\x00\x00\x00H\x00\x00\x00\x01I\x00\x00\x00\x00J\x00\x00\x00\x00K\x00\x00\x00\x00Z\x00\x00\x00\x01[\x00\x00\x00\x01\\\x00\x00\x00\x00]\x00\x00\x00\x00\x00'

	tc = TerminalConfig()
	tc.set_terminal_modes(terminal_modes)
