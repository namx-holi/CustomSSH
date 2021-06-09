import socket
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

import protocol
from packet import PacketHandler
from helpers import ReadHelper, WriteHelper
from public_key_handler import PublicKeyHandler
from diffie_hellman_handler import DiffieHellmanHandler

HOST = "127.0.0.1"
PORT = 2222

V_C = b"SSH-2.0-Bingus"

ph = PacketHandler()
dh_handler = DiffieHellmanHandler()


def test():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOST, PORT))

	def send_packet(msg):
		print(" [*] Sending ", msg)
		if isinstance(msg, protocol.SSH_MSG):
			packet = ph.new_packet(msg.to_bytes())
			raw = packet.compile()
		else:
			raw = msg
		s.sendall(raw)

	def recv_packet():

		print(" [*] Receiving...", end="")
		packet = ph.read_packet_from_conn(s)
		msg = protocol.SSH_MSG.create_from_packet(packet)
		print("\r [*] Received", msg)
		return msg

	# Sending our CLIENT_PROTOCOL
	send_packet(V_C + b"\r\n")

	# Receive the server's protocol thing
	V_S = b""
	while not V_S.endswith(b"\r\n"):
		V_S += s.recv(1)
	V_S = V_S.rstrip(b"\r\n")
	print(" [*] Received", V_S)

	# Send our supposed algorithms to force a set
	cookie = b"\x00"*16
	kex_algorithms = ["diffie-hellman-group14-sha1"]
	server_host_key_algorithms = ["ssh-rsa"]
	encryption_algorithms = ["aes128-cbc"]
	mac_algorithms = ["hmac-md5"]
	comp_algorithms = ["none"]
	languages = []
	first_kex_packet_follows = False

	client_kexinit = protocol.SSH_MSG_KEXINIT(
		cookie=cookie,
		kex_algorithms=kex_algorithms,
		server_host_key_algorithms=server_host_key_algorithms,
		encryption_algorithms_client_to_server=encryption_algorithms,
		encryption_algorithms_server_to_client=encryption_algorithms,
		mac_algorithms_client_to_server=mac_algorithms,
		mac_algorithms_server_to_client=mac_algorithms,
		compression_algorithms_client_to_server=comp_algorithms,
		compression_algorithms_server_to_client=comp_algorithms,
		languages_client_to_server=languages,
		languages_server_to_client=languages,
		first_kex_packet_follows=first_kex_packet_follows)
	# Sending server KEXINIT
	send_packet(client_kexinit)
	I_C = client_kexinit.to_bytes()

	# Set up key stuff
	ph.prepare_algorithms(
		enc_c_to_s=encryption_algorithms[0],
		enc_s_to_c=encryption_algorithms[0],
		mac_c_to_s=mac_algorithms[0],
		mac_s_to_c=mac_algorithms[0],
		com_c_to_s=comp_algorithms[0],
		com_s_to_c=comp_algorithms[0])

	# Receiving server KEXINIT
	server_kexinit = recv_packet()
	I_S = server_kexinit.to_bytes()

	p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
	g = 2
	x = 12345
	e = pow(g, x, p)

	client_kexdh_init = protocol.SSH_MSG_KEXDH_INIT(e)
	# Sending client KEXDH_INIT
	send_packet(client_kexdh_init)

	# Receiving server KEXDH_INIT_REPLY
	server_kexdh_reply = recv_packet()

	K_S = server_kexdh_reply.K_S
	f = server_kexdh_reply.f
	H_sig = server_kexdh_reply.H_sig

	K = pow(f, x, p)
	print(" [!] SHARED SECRET SET TO", K)

	print("")
	r = ReadHelper(K_S)
	K_S_type = r.read_string()
	K_S_e = r.read_mpint()
	K_S_n = r.read_mpint()


	r = ReadHelper(H_sig)
	H_sig_type = r.read_string()
	H_sig = r.read_string()

	print("")
	print("Attempting to construct our own H_sig")
	w = WriteHelper()
	w.write_string(V_C)
	w.write_string(V_S)
	w.write_string(I_C)
	w.write_string(I_S)
	w.write_string(K_S)
	w.write_mpint(e)
	w.write_mpint(f)
	w.write_mpint(K)
	H_raw = SHA1.new(w.data)
	H = H_raw.digest()
	session_id = H # exchange hash h from the first key exchange
	print(f"  V_C: {V_C}")
	print(f"  V_S: {V_S}")
	print(f"  I_C: {I_C[0:16]}...")
	print(f"  I_S: {I_S[0:16]}...")
	print(f"  K_S: {K_S[0:16]}...")
	print("H starts with", H[0:4])


	pk_handler = PublicKeyHandler("ssh-rsa")
	if PORT == 22:
		pk_handler.read_key("localhost.priv")
	else:
		pk_handler.read_key("CustomSSH.priv")
	server_key = pk_handler.key

	H_H_raw = SHA1.new(H)
	sig = pkcs1_15.new(server_key).sign(H_H_raw)
	print("  Given H_sig starts with:     ", H_sig[0:4])
	print("  Generated H_sig starts with: ", sig[0:4])
	print("")

	# new keys!
	server_new_keys = recv_packet()
	client_new_keys = protocol.SSH_MSG_NEWKEYS()
	send_packet(client_new_keys)
	dh_handler.K = K
	dh_handler.H = H
	dh_handler.session_id = session_id
	dh_handler.set_algorithm(kex_algorithms[0])
	dh_handler.generate_keys()
	print("Tried to generate keys")

	ph.set_prepared_algorithms()
	ph.set_keys( # keys swapped around as we are client now
		iv_c_to_s=dh_handler.initial_iv_s_to_c,
		iv_s_to_c=dh_handler.initial_iv_c_to_s,
		enc_c_to_s=dh_handler.enc_key_s_to_c,
		enc_s_to_c=dh_handler.enc_key_c_to_s,
		mac_c_to_s=dh_handler.mac_key_s_to_c,
		mac_s_to_c=dh_handler.mac_key_c_to_s)

	# Sending bogus service request
	service_request = protocol.SSH_MSG_SERVICE_REQUEST("ssh-userauth")
	send_packet(service_request)

	print("waiting on resp")
	_ = recv_packet()
