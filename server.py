import socket

# from connection_handler import ConnectionHandler
from protocol import ProtocolHandler


# Mock server for now.


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


s.bind(("", 2222))
s.listen(1)

while True:
	print(" [*] Listening for connection")
	conn, addr = s.accept()
	try:
		print(f" [*] Connection from {addr[0]}:{addr[1]}")
		c = ProtocolHandler(conn, addr)
		c.start()

	finally:
		conn.close()

print("Server stopped")
