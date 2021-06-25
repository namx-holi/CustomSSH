
from ssh_msg import (
	SSH_MSG_USERAUTH_REQUEST,
	SSH_MSG_USERAUTH_FAILURE,
	SSH_MSG_USERAUTH_SUCCESS,
	SSH_MSG_USERAUTH_BANNER,
	SSH_MSG_USERAUTH_MISC_RESP,
	SSH_MSG_USERAUTH_PK_OK,
	SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)

from ssh_msg import (
	SSH_MSG_CHANNEL_OPEN,
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
	SSH_MSG_CHANNEL_OPEN_FAILURE,
	SSH_MSG_CHANNEL_WINDOW_ADJUST,
	SSH_MSG_CHANNEL_DATA,
	SSH_MSG_CHANNEL_EXTENDED_DATA,
	SSH_MSG_CHANNEL_EOF,
	SSH_MSG_CHANNEL_CLOSE,
	SSH_MSG_CHANNEL_REQUEST,
	SSH_MSG_CHANNEL_SUCCESS,
	SSH_MSG_CHANNEL_FAILURE)


fake_db = {
	"admin": ("q", False),
	"user": ("pass123", False),
	"bingus": ("bingus", True)
}


class LoginManager:

	def __init__(self):
		self.sessions = {}
		self.auths = ["password"]


	def new_session(self, protocol_handler, username):
		session = LoginSession(self, protocol_handler, username)
		self.sessions[username] = session
		return session


	def handle_userauth_request(self, protocol_handler, data) -> ("session", "reply"):
		username = data.user_name
		service_name = data.service_name
		method_name = data.method_name
		print("Service name is....", service_name)

		if method_name == "publickey":
			print("TODO: Handling publickey")
			reply = SSH_MSG_USERAUTH_FAILURE(self.auths, False)
			return None, reply

		elif method_name == "password":
			if data.changing_password:
				session, reply = self.handle_password_change_auth(
					username=username,
					password=data.password,
					new_password=data.new_password)
			else:
				session, reply = self.handle_password_auth(
					protocol_handler=protocol_handler,
					username=username,
					password=data.password)

			return session, reply

		elif method_name == "hostbased":
			print("TODO: Handling hostbased")
			reply = SSH_MSG_USERAUTH_FAILURE(self.auths, False)
			return None, reply

		elif method_name == "none":
			reply = SSH_MSG_USERAUTH_FAILURE(self.auths, False)
			return None, reply

		else:
			reply = SSH_MSG_USERAUTH_FAILURE(self.auths, False)
			return None, reply


	def handle_password_auth(self, protocol_handler, username, password):
		# Verify username/password combo
		# TODO: Handle in a real way
		pw, needs_to_be_changed = fake_db.get(username)
		if pw is None or pw != password:
			reply = SSH_MSG_USERAUTH_FAILURE(self.auths, False)
			return None, reply

		# If the password needs to be changed, reply with that instead
		# TODO: Handle this in a real way
		if needs_to_be_changed:
			reply = SSH_MSG_USERAUTH_PASSWD_CHANGEREQ("Password needs to be changed.")
			return None, reply

		# Creds were verified, return with a session
		session = self.new_session(protocol_handler, username)
		reply = SSH_MSG_USERAUTH_SUCCESS()
		return session, reply


	def handle_password_change_auth(self, username, password, new_password):
		# Verify username/password combo
		# TODO: Handle in a real way
		pw, needs_to_be_changed= fake_db.get(username)
		if pw is None or pw != password:
			reply = SSH_MSG_USERAUTH_FAILURE(self.auths, False)
			return None, reply

		# Try to change the password
		try:
			if len(new_password) < 8:
				pw_change_success = False
				msg = "New password must be 8 characters or more."
			else:
				# TODO: Handle this correctly
				fake_db[username] = (new_password, False)
				pw_change_success = True
				msg = ""
		except:
			# Password not changed because it was not supported
			reply = SSH_MSG_USERAUTH_FAILURE(self.auth, False)
			return None, reply

		# New password was not acceptable
		if not pw_change_success:
			reply = SSH_MSG_USERAUTH_PASSWD_CHANGEREQ(msg)
			return None, reply

		# Requires more authentication
		# TODO:
		if False:
			reply = SSH_MSG_USERAUTH_FAILURE(self.auth, True)
			return None, reply

		# Password was changed and auth is successful
		session = self.new_session(username)
		reply = SSH_MSG_USERAUTH_SUCCESS()

		return session, reply



class LoginSession:

	def __init__(self, login_manager, protocol_handler, username):
		self.login_manager = login_manager
		self.protocol_handler = protocol_handler
		self.username = username
		self.channels = {}

	def handle_channel_open(self, data):
		channel_type = data.channel_type
		sender_channel = data.sender_channel
		initial_window_size = data.initial_window_size
		maximum_packet_size = data.maximum_packet_size

		if channel_type == "session":
			channel, reply = self.handle_session_channel_open(
				sender_channel=sender_channel,
				initial_window_size=initial_window_size,
				maximum_packet_size=maximum_packet_size)
			return reply

		elif channel_type == "x11":
			print("TODO: Handling x11")
			reply = SSH_MSG_CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED(
				sender_channel, "x11 is not supported")
			return reply

		elif channel_type == "forwarded-tcpip":
			print("TODO: Handling forwarded-tcpip")
			reply = SSH_MSG_CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED(
				sender_channel, "forwarded-tcpip is not supported")
			return reply

		elif channel_type == "direct-tcpip":
			print("TODO: Handling direct-tcpip")
			reply = SSH_MSG_CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED(
				sender_channel, "direct-tcpip is not supported")
			return reply

		else:
			reply = SSH_MSG_CHANNEL_OPEN_FAILURE.UNKNOWN_CHANNEL_TYPE(
				sender_channel, f"unknown channel type {channel_type}")
			return reply

	def handle_session_channel_open(self,
		sender_channel, initial_window_size, maximum_packet_size
	):
		channel = Channel(
			self,
			sender_channel,
			initial_window_size,
			maximum_packet_size)

		# If anything went wrong in creating the channel...?
		if False:
			reply = SSH_MSG_CHANNEL_OPEN_FAILURE.CONNECT_FAILED(
				sender_channel, "some desc here")
			return None, reply

		# If a resource shortage, ie ran out of channels?
		if False:
			reply = SSH_MSG_CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE(
				sender_channel, "some desc here")
			return None, reply

		# Store the channel under the server's channel num to make
		#  it easy to look up when receiving a request
		self.channels[channel.server_channel] = channel


		reply = SSH_MSG_CHANNEL_OPEN_CONFIRMATION(
			channel.client_channel, channel.server_channel,
			initial_window_size, maximum_packet_size)
		return channel, reply

	# TODO: Handle other channel types

	def handle_channel_request(self, data):
		recipient_channel = data.recipient_channel
		request_type = data.request_type
		want_reply = data.want_reply

		channel = self.channels[recipient_channel]

		if request_type == "pty-req":
			term_environment_variable = data.term_environment_variable
			terminal_width = data.terminal_width
			terminal_height = data.terminal_height
			terminal_width_pixels = data.terminal_width_pixels
			terminal_height_pixels = data.terminal_height_pixels
			encoded_terminal_modes = data.encoded_terminal_modes
			reply = channel.handle_setup_pty_req(
				term_environment_variable,
				terminal_width,
				terminal_height,
				terminal_width_pixels,
				terminal_height_pixels,
				encoded_terminal_modes)
			return reply if want_reply else None

		elif request_type == "x11-req":
			print("TODO: Handling x11-req")
			if want_reply:
				reply = SSH_MSG_CHANNEL_FAILURE(channel.client_channel)
				return reply
			return None

		elif request_type == "env":
			variable_name = data.variable_name
			variable_value = data.variable_value
			reply = channel.handle_setup_env(
				variable_name,
				variable_value)
			return reply if want_reply else None

		elif request_type == "shell":
			reply = channel.handle_setup_shell()
			return reply if want_reply else None

		elif request_type == "exec":
			print("TODO: Handling exec")
			if want_reply:
				reply = channel.SSH_MSG_CHANNEL_FAILURE()
				return reply
			return None

		elif request_type == "subsystem":
			print("TODO: Handling subsystem")
			if want_reply:
				reply = channel.SSH_MSG_CHANNEL_FAILURE()
				return reply
			return None

		else:
			# Unknown request type
			if want_reply:
				reply = channel.SSH_MSG_CHANNEL_FAILURE()
				return reply
			return None

	def handle_channel_data(self, data):
		recipient_channel = data.recipient_channel

		# If extended data, read the type too
		if isinstance(data, SSH_MSG_CHANNEL_DATA):
			data_type_code = 0
		elif isinstance(data, SSH_MSG_CHANNEL_EXTENDED_DATA):
			data_type_code = data.data_type_code
		data = data.data

		channel = self.channels[recipient_channel]
		reply = channel.handle_data(data, data_type_code)
		return reply



class Channel:

	channel_count = 0

	def __init__(self, session,
		client_channel, initial_window_size, maximum_packet_size
	):
		Channel.channel_count += 1
		self.session = session
		self.server_channel = Channel.channel_count
		self.client_channel = client_channel
		self.channel_type = None
		self.env = {}

	def SSH_MSG_CHANNEL_SUCCESS(self):
		return SSH_MSG_CHANNEL_SUCCESS(self.client_channel)

	def SSH_MSG_CHANNEL_FAILURE(self):
		return SSH_MSG_CHANNEL_FAILURE(self.client_channel)

	def SSH_MSG_CHANNEL_DATA(self, data):
		return SSH_MSG_CHANNEL_DATA(self.client_channel, data)

	def handle_setup_pty_req(self,
		term_environment_variable,
		terminal_width, terminal_height,
		terminal_width_pixels, terminal_height_pixels,
		encoded_terminal_modes
	):
		print("Handling setting up pty-req in channel")
		self.channel_type = "pty-req"
		self.terminal_width = terminal_width
		self.terminal_height = terminal_height
		self.terminal_width_pixels = terminal_width_pixels
		self.terminal_height_pixels = terminal_height_pixels

		# Read the terminal modes
		print("TODO: Handle encoded terminal modes")
		self.encoded_terminal_modes = encoded_terminal_modes

		# print("  term width is", terminal_width)
		# print("  term height is", terminal_height)
		# print("  term width px is", terminal_width_pixels)
		# print("  term height px is", terminal_height_pixels)
		# print("  term modes are", encoded_terminal_modes)

		return self.SSH_MSG_CHANNEL_SUCCESS()

	def handle_setup_env(self, variable_name, variable_value):
		print("Handling setting env variable")
		print(f"  {variable_name} = {variable_value}")

		self.env[variable_name] = variable_value
		return self.SSH_MSG_CHANNEL_SUCCESS()

	def handle_setup_shell(self):
		print("Handling setting shell")

		# TODO: Do some things? IDK
		...

		return self.SSH_MSG_CHANNEL_SUCCESS()

	def handle_data(self, data, data_type_code):
		print("Handling data")

		print("  Data was", data)
		print("  Data type code was", data_type_code)

		# TODO: Do some things? IDK
		thing = self.SSH_MSG_CHANNEL_DATA(
			f"bingus. ur data was {data}\n")
		return thing

	def send_stdout(self, data):
		msg = SSH_MSG_CHANNEL_DATA(data)
		self.session.protocol_handler.send_packet(msg)


	def send_stderr(self, data):
		msg = SSH_MSG_CHANNEL_EXTENDED_DATA(data, 1)
		self.session.protocol_handler.send_packet(msg)
