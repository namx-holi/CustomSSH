
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


