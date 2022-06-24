from os import urandom

from config import Config
from ssh_trans.packet_handler import PacketHandler

import messages

# Lists of available algorithms
from algorithms.compression import algorithms as compression_algorithms
from algorithms.encryption import algorithms as encryption_algorithms
from algorithms.key_exchange import algorithms as key_exchange_algorithms
from algorithms.mac import algorithms as mac_algorithms
from algorithms.public_key import algorithms as public_key_algorithms


# Helper method to find matches between algorithms
def find_match(client_list, server_list):
	return next((
		algo for algo in set(client_list)
		if algo in server_list), None)



class AlgorithmSetError(Exception): pass
class AlgorithmSet:
	def __init__(self, client_kexinit, server_kexinit):
		# Find matches
		key_exchange_algorithm = find_match(client_kexinit.kex_algorithms, server_kexinit.kex_algorithms)
		public_key_algorithm = find_match(client_kexinit.server_host_key_algorithms, server_kexinit.server_host_key_algorithms)
		serverside_encryption_algorithm = find_match(client_kexinit.encryption_algorithms_server_to_client, server_kexinit.encryption_algorithms_server_to_client)
		serverside_compression_algorithm = find_match(client_kexinit.compression_algorithms_server_to_client, server_kexinit.compression_algorithms_server_to_client)
		serverside_mac_algorithm = find_match(client_kexinit.mac_algorithms_server_to_client, server_kexinit.mac_algorithms_server_to_client)
		clientside_encryption_algorithm = find_match(client_kexinit.encryption_algorithms_client_to_server, server_kexinit.encryption_algorithms_client_to_server)
		clientside_compression_algorithm = find_match(client_kexinit.compression_algorithms_client_to_server, server_kexinit.compression_algorithms_client_to_server)
		clientside_mac_algorithm = find_match(client_kexinit.mac_algorithms_client_to_server, server_kexinit.mac_algorithms_client_to_server)

		# Raise an exception if there is no match for any
		if key_exchange_algorithm is None: raise AlgorithmSetError("No key exchange algorithm")
		if public_key_algorithm is None: raise AlgorithmSetError("No public key algorithm")
		if serverside_encryption_algorithm is None: raise AlgorithmSetError("No serverside encryption algorithm")
		if serverside_compression_algorithm is None: raise AlgorithmSetError("No serverside compression algorithm")
		if serverside_mac_algorithm is None: raise AlgorithmSetError("No serverside mac algorithm")
		if clientside_encryption_algorithm is None: raise AlgorithmSetError("No clientside encryption algorithm")
		if clientside_compression_algorithm is None: raise AlgorithmSetError("No clientside compression algorithm")
		if clientside_mac_algorithm is None: raise AlgorithmSetError("No clientside mac algorithm")

		# Actually set the algorithms
		self.key_exchange_algorithm = key_exchange_algorithms[key_exchange_algorithm]
		self.public_key_algorithm = public_key_algorithms[public_key_algorithm]
		self.serverside_encryption_algorithm = encryption_algorithms[serverside_encryption_algorithm]
		self.serverside_compression_algorithm = compression_algorithms[serverside_compression_algorithm]
		self.serverside_mac_algorithm = mac_algorithms[serverside_mac_algorithm]
		self.clientside_encryption_algorithm = encryption_algorithms[clientside_encryption_algorithm]
		self.clientside_compression_algorithm = compression_algorithms[clientside_compression_algorithm]
		self.clientside_mac_algorithm = mac_algorithms[clientside_mac_algorithm]



class ClientHandler:

	def __init__(self, conn):
		# Exchange identification strings
		self.client_identification_string = conn.recv(255)
		self.server_identification_string = Config.IDENTIFICATION_STRING.encode("utf-8")
		for line in Config.IDENTIFICATION_COMMENTS:
			conn.send(line.encode("utf-8"))
		conn.send(self.server_identification_string)

		# Start our packet handler
		self.packet_handler = PacketHandler(conn)

		# Saved instances of our algorithm exchange
		self.client_kexinit = None
		self.server_kexinit = None

		# If the packet reading loop is running. On client disconnect,
		#  the loop method should end.
		self.running = False


	def loop(self):
		self.running = True
		while self.running:
			msg = self.packet_handler.read_message()
			self.handle_msg(msg)


	def handle_msg(self, msg):
		if isinstance(msg, messages.SSH_MSG_KEXINIT):
			# Store the clients algorithms
			self.client_kexinit = msg

			# Respond with our available algorithms
			cookie = urandom(16)
			resp = messages.SSH_MSG_KEXINIT(
				cookie=cookie,
				kex_algorithms=key_exchange_algorithms.keys(),
				server_host_key_algorithms=public_key_algorithms.keys(),
				encryption_algorithms_client_to_server=encryption_algorithms.keys(),
				encryption_algorithms_server_to_client=encryption_algorithms.keys(),
				mac_algorithms_client_to_server=mac_algorithms.keys(),
				mac_algorithms_server_to_client=mac_algorithms.keys(),
				compression_algorithms_client_to_server=compression_algorithms.keys(),
				compression_algorithms_server_to_client=compression_algorithms.keys(),
				languages_client_to_server=Config.LANGUAGES,
				languages_server_to_client=Config.LANGUAGES,
				first_kex_packet_follows=False # Handling otherwise is hard.
			)
			self.server_kexinit = resp
			self.packet_handler.send_message(resp)

			try:
				self.algorithms = AlgorithmSet(self.client_kexinit, self.server_kexinit)
			except AlgorithmSetError as e:
				# If there are no matches for any of the algorithms, we
				#  can drop our connection right here as the client would
				#  too.
				print(e.args)
				self.running = False
				return
