
from ssh_msg import (
	SSH_MSG_USERAUTH_REQUEST,
	SSH_MSG_USERAUTH_FAILURE,
	SSH_MSG_USERAUTH_SUCCESS,
	SSH_MSG_USERAUTH_BANNER,
	SSH_MSG_USERAUTH_MISC_RESP,
	SSH_MSG_USERAUTH_PK_OK,
	SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)


fake_db = {
	"admin": ("password", False),
	"user": ("pass123", False),
	"bingus": ("bingus", True)
}


class LoginManager:

	def __init__(self):
		self.sessions = {}
		self.auths = ["password"]


	def new_session(self, username):
		session = LoginSession(self, username)
		self.sessions[username] = session
		return session


	def handle_userauth_request(self, data) -> ("session", "reply"):
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


	def handle_password_auth(self, username, password):
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
		session = self.new_session(username)
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
	def __init__(self, login_manager, username):
		self.login_manager = login_manager
		self.username = username
