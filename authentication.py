
from config import Config
from messages import (
	SSH_MSG_USERAUTH_BANNER,
	SSH_MSG_USERAUTH_FAILURE,
	SSH_MSG_USERAUTH_SUCCESS)


# TODO: Pass service name to this exception
class ServiceNotAvailable(Exception):
	...



class AuthenticationHandler:

	def __init__(self):
		# What user is attempting to log in, and for what service
		self.user_name = None
		self.service_name = None

		# If the user is actually logged in
		self.is_authenticated = False

		# Available usernames and services. This should be retrieved
		#  somehow on start up. TODO
		self.available_services = ["ssh-connection"]

		# TODO: Move these to a particular user handler
		self.auth_required = Config.AUTH_REQUIRED
		self.available_users = {"user"}
		self.available_methods = {"password"}
		self.successful_methods = set()


	def get_banner(self):
		banner = SSH_MSG_USERAUTH_BANNER(message=Config.USERAUTH_BANNER)
		return banner


	def handle_USERAUTH_REQUEST(self, msg):
		# SSH-USERAUTH 5.

		# The user_name and service_name MAY change. These MUST be
		#  checked, and MUST flush any authentication states if they
		#  change. If it is unable to flush, it MUST disconnect if the
		#  user_name or service_name change.
		if msg.user_name != self.user_name or msg.service_name != self.service_name:
			self.successful_methods.clear()
		self.user_name = msg.user_name
		self.service_name = msg.service_name

		# If the requested service is not available, the server MAY
		#  disconnect immediately or at any later time. Sending a proper
		#  disconnect message is RECOMMENDED. In any case, if the
		#  service does not exist, authentication MUST NOT be accepted.
		if self.service_name not in self.available_services:
			raise ServiceNotAvailable()

		# Remaining authentication methods left to try for the client
		remaining_auths = list(self.available_methods.difference(self.successful_methods))

		# If the requested user name does not exist, the server MAY
		#  disconnect, or MAY send a bogus list of acceptable
		#  authentication method name values, but never accept any. This
		#  makes it possible for the server to avoid disclosing
		#  information on which accounts exist. In any case, if the
		#  user name does not exist, the authentication request MUST NOT
		#  be accepted.
		if self.user_name not in self.available_users:
			return SSH_MSG_USERAUTH_FAILURE(
				available_authentications=remaining_auths,
				partial_success=False)

		method_name = msg.method_name

		# SSH-USERAUTH 7.
		if method_name == "publickey":
			# TODO
			msg.authenticating
			msg.algorithm_name
			msg.key_blob
			msg.public_key
			msg.signature
			raise Exception("publickey not implemented")

		# SSH-USERAUTH 8.
		elif method_name == "password":
			changing_password = msg.changing_password
			password = msg.password

			# Check password
			if password != Config.PASSWORD:
				return SSH_MSG_USERAUTH_FAILURE(
					available_authentications=remaining_auths,
					partial_success=False)

			# Setting a new password if needed
			if changing_password:
				# TODO: Handle this for real
				new_password = msg.new_password
				return SSH_MSG_USERAUTH_FAILURE(
					available_authentications=remaining_auths,
					partial_success=False)

			# Successful login!
			return SSH_MSG_USERAUTH_SUCCESS()

		# SSH-USERAUTH 9.
		elif method_name == "hostbased":
			# TODO
			msg.algorithm_name
			msg.certificates
			msg.host_name
			msg.client_user_name
			msg.signature
			raise Exception("hostbased not implemented")

		# SSH-USERAUTH 5.2.
		elif method_name == "none":
			# MUST always reject, unless the client is to be granted
			#  access without any authentication, in which case, MUST
			#  accept this requst. The main purpose of this request is
			#  to get the list of supported methods from the server.
			if not self.auth_required:
				self.is_authenticated = True
				return SSH_MSG_USERAUTH_SUCCESS()

			return SSH_MSG_USERAUTH_FAILURE(
				available_authentications=remaining_auths,
				partial_success=True)

		# Unhandled authentication method
		else:
			return SSH_MSG_USERAUTH_FAILURE(
				available_authentications=remaining_auths,
				partial_success=True)
