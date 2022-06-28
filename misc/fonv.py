
"""
Import this at the top of main_test to turn SSH client into a terminal
from FONV
"""
import time

from authentication import AuthenticationHandler
from client_handler import ClientHandler
from messages import (
	SSH_MSG_USERAUTH_BANNER,
	SSH_MSG_USERAUTH_FAILURE,
	SSH_MSG_USERAUTH_SUCCESS)


# New attributes
ClientHandler.startup_sent = False

# New USERAUTH handler that sends the FONV terminal startup
def handle_SSH_MSG_USERAUTH_REQUEST(self, msg):
	# Helper method to reduce code
	def send_banner_instant(msg):
		self.message_handler.send(SSH_MSG_USERAUTH_BANNER(message=msg))

	# Helper that sends banners one letter a time
	def send_banner(msg):
		for letter in msg:
			self.message_handler.send(SSH_MSG_USERAUTH_BANNER(message=letter))
			time.sleep(0.5/30)
	def send_banner_typed(msg):
		for letter in msg:
			self.message_handler.send(SSH_MSG_USERAUTH_BANNER(message=letter))
			time.sleep(2/30)

	if not self.startup_sent:
		self.startup_sent = True
		# send_banner_instant("\n"*24) # Attempt to clear screen
		send_banner_instant("\e[1;1H\e[2J\r" + " "*80 + "\r")
		send_banner("SECURITY RESET...")
		send_banner_instant("\r                 \n")
		send_banner("WELCOME TO ROBCO INDUSTRIES (TM) TERMLINK\n")
		send_banner("\n")
		send_banner(">")
		time.sleep(1)
		send_banner_typed("SET TERMINAL/INQUIRE\n")
		send_banner("\n")
		send_banner("RIT-V300\n")
		send_banner("\n")
		send_banner(">")
		time.sleep(1)
		send_banner_typed("SET FILE/PROTECTION-OWNER:RWED ACCOUNTS.F\n")
		send_banner(">")
		time.sleep(1)
		send_banner_typed("SET HALT RESTART/MAINT\n")
		send_banner("\n")
		send_banner("Initialising Robco Industries(TM) HM Boot Agent v2.3.0\n")
		send_banner("RETROS BIOS\n")
		send_banner("RBIOS-4.02.80.00 52EE5.E7.E8\n")
		send_banner("Copyright 2201-2203 Robco Ind.\n")
		send_banner("Uppermem: 64 KB\n")
		send_banner("Root (5A8)\n")
		send_banner("Maintenance Mode\n")
		send_banner("\n")
		send_banner(">")
		time.sleep(1)
		send_banner_typed("RUN DEBUG/ACCOUNTS.F\n")
		time.sleep(19/30)

	# Handle the request
	resp = self.auth_handler.handle_USERAUTH_REQUEST(msg)
	self.message_handler.send(resp)


# Override methods
ClientHandler.handle_SSH_MSG_USERAUTH_REQUEST = handle_SSH_MSG_USERAUTH_REQUEST
