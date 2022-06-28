
"""
This file is used to work on client handling without having to write
the whole server beforehand
"""
import socket
from client_handler import ClientHandler
from authentication import AuthenticationHandler


def main():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("", 2222))
	s.listen(1)

	# Set up a handler for authentication
	auth_handler = AuthenticationHandler()

	# Wait for a connection
	print("Running...")
	while True:
		conn, addr = s.accept()
		c = ClientHandler(conn, auth_handler)
		c.loop()
		print("Exited gracefully")
		print("\n"*4)
		return

main()
