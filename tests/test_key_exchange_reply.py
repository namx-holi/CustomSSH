
import helpers
from protocol import SSH_MSG_KEXDH_REPLY
from public_key_handler import PublicKeyHandler

pk_handler = PublicKeyHandler("ssh-rsa")
pk_handler.read_key("CustomSSH.priv")
K_S = pk_handler.key_b


def test():
	print("Creating a SSH_MSG_KEXDH_REPLY packet")

	# mpint
	f = int.from_bytes(b"\x7f"*256, "big", signed=True)

	# string
	H_sig = b"\xab" * 271

	msg = SSH_MSG_KEXDH_REPLY(
		K_S,
		f,
		H_sig)
	data = msg.to_bytes()

	# Try read the msg manually
	print("Reading the generated packet")
	read_manually(data)

	print("")

	sent_packet = b'\x1f\x00\x00\x01\x17\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x01\x00\xbd\x04\x06\x15\xf5\x0f\xb4I\x90l\xb7\xbe\x8f\xe0\nG\x0f\xfem\xf67\xceb\xc2\xc0\xfc\xb4h\xb0)F\x84w\xb9z\xce/\xc3\xc8\xa9\x822M\xc6\xa2\xc6\xc7\xc8\xc4"d;\x9d\x96s\xcd\xf4!\xa8\x7fLk\xb9-\x91\x87e\xa1+\x8c\x16\x0c\xd9\x05&\x93X\x84\xb2\xe4\x8d\x98\xe2\xa3\xac\xd9\xa3\xf6\xd0}\x82*\xae\xb3\n\x9c\xe0\xf2C\xceN\xd1\x0c\xc7\xea\x90x\xfbQ8\xe5TO%\x1c\x95\x80\x0b\x9b#(\xbdk!\xf4\xc8E\xa7=#,\x97)!}\xa7\x02\x08tx!r\xbe\xa6f\xb7\x0f\x9cq_C\xe6(d\x89\xfaK.\xbd\xea\xcf\\w\x9dZ\x82*\xcco\xae\xc1i\x139\x8aX\x0f\x17\x99\x96\xb3\x92*\xce\xc4X\r\x9b\xca\xbd\x9f\x0bA#$\x19p\xb3\x8a{rH\xe1\xff\x00`\x89\xc9b7\xc7-Z\xd1\x1eBpwX\x0c\xaaz\xd4\x80\x1b\xa7\x00\x94\xb2\x85Q>! 9\x7f\x1fTqG\xe5\x03\xfdT\x01\xe8\x1fgq`\x148\x9c\xfba\'\x00\x00\x01\x004,s*b,W\x90\x07^\xe9\xb8c\xc3\xf4D\\@\x0c\xcc\x9f4\x05\x14}D\x1c\xdfN\xef\x9a\xdb\x96\x9d\\\xd6\xce\x84\xe8\x9a\x87\x1dWD\x0e\x14>k"\x04\x82\xfbP\x18(\x05\x97\x0f]\xd6\x95\xe2\xc1O\xcc\xcf\xd5\x80Z\xf0C\xcb\x86r\x1c\x0f\x1a\xb9\xe7~\x89w\x13\xe37+\xd0IY\xe23\xa3H\xc7\xfc\x85@y\xf1:\xce\x19}\xa5\x9f\xd3\xb8\xd1\x0b\xa9\x86\xed\xd7.\x00o\xf4\x16@\x9d\xf8\x87\x0b\x81\x9ar\x87IvD\xa5y\x89\xcc\xb3\xf5\x0f\xe1\xa8\x13+\x0e\xc9\x99\xdd\x06P,\x83\xf4j\x8bs\x0cG\x8f\x141hp$\xcd?\xa2\xb9\x1a\x1f\x9aO\xcf/\xb4\xa7\xfc\xfb\xe5\\\x8e\x1f\xff\xf0gf\x93\x86\xbb\x0c\xde\x90VS\x8b\xba\xac\x7f\xd3y\xec2\xf9X\x89\xde\xa1\xd9\x1b\xc8\x9bx\xc1\xf3YW\xf6\xd2\xf1\xbd|1\xd6\xaf\xfdYH\xacm\x13a\xea\tj\xbe\x97/\xffm\xc9H\xb2\x8cJ\x90\xfc0\x17n-\xc8\xa3\xe6\x8c\x82\x8a\x81*\xe3\x00\x00\x00\x14\xc2Q\x9d\xe3\xc7*\x7f\x0b\x1e\x0e\xa8s\xbd+\xe9\xe6\xdbq2\x03'
	print("Reading the sent packet")
	read_manually(sent_packet)





def read_manually(data):
	print("data is", data)

	reader = helpers.ReadHelper(data)

	msg_code = reader.read_uint8()
	print("msg_code was", msg_code)

	host_key_length = reader.read_uint32()
	print("host_key_length is", host_key_length)

	host_key_type_length = reader.read_uint32()
	host_key_type = reader.read_bytes(host_key_type_length)
	print("host_key_type_length is", host_key_type_length)
	print("host_key_type is", host_key_type)

	rsa_exponent_len = reader.read_uint32()
	rsa_exponent = reader.read_bytes(rsa_exponent_len)
	print("rsa_exponent_len is", rsa_exponent_len)
	print("rsa_exponent is", rsa_exponent)

	rsa_modulus_len = reader.read_uint32()
	rsa_modulus = reader.read_bytes(rsa_modulus_len)
	print("rsa_modulus_len is", rsa_modulus_len)
	print("rsa_modulus is", rsa_modulus)

	DH_server_f_len = reader.read_uint32()
	DH_server_f = reader.read_bytes(DH_server_f_len)
	print("DH_server_f_len is", DH_server_f_len)
	print("DH_server_f is", DH_server_f)

	KEX_H_signature_len = reader.read_uint32()
	KEX_H_signature = reader.read_bytes(KEX_H_signature_len)
	print("KEX_H_signature_len is", KEX_H_signature_len)
	print("KEX_H_signature is", KEX_H_signature)
