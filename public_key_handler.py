from Crypto.Hash import SHA1
from Crypto.PublicKey import DSA, RSA
from Crypto.Signature import pkcs1_15

from helpers import GenericHandler, WriteHelper

"""
RFC4253, 6.6. Public Key Algorithms
	This protocol has been designed ot operate with almost any public key
	format, encoding, and algorithm (signature and/or encryption).

	There are several aspects that define a public key type:

	o  Key format: how is the key encoded and how are certificates
	   represented.  The key blobs in this protocol MAY contain
	   certificates in additional to keys.

	o  Signature and/or encryption algorithms.  Some key types may not
	   support both signing and encryption.  Key usage may also be
	   restricted by policy statements (e.g., in certificates).  In this
	   case, different key types SHOULD be defined for the different
	   policy alternatives.

	o  Encoding of signatures and/or encrypted data.  This includes but
	   is not limited to padding, byte order, and data formats.

	The following public key and/or certificate formats are currently
	defined:

	ssh-dss			REQUIRED		sign	Raw DSS Key
	ssh-rsa			RECOMMENDED		sign	Raw RSA Key
	pgp-sign-rsa	OPTIONAL		sign	OpenPGP certificates (RSA Key)
	pgp-sign-dss	OPTIONAL		sign	OpenPGP certificates (DSS Key)

	Additional key types may be defined, as specified in [SSH-ARCH] and
	in [SSH-NUMBERS].

	The key type MUST always be explicitly known (from algorithm
	negotiation or some other source).  It is not normally included in
	the key blob.

	Certificates and public keys are encoded as follows:

		string	certificate or public key format identifier
		byte[n]	key/certificate data

	The certificate part may be a zero length string, but a public key is
	required.  This is the public key that will be used for
	authentication.  The certificate sequence contained in the
	certificate blob can be used to provide authorization.

	Public key/certificate formats that do not explicitly specify a
	signature format identifier MUST use the public key/certificate
	format identifier as the signature identifier.

	Signatures are encoded as follows:

		string	signature format identifier (as specified by the
				public key/certificate format)
		byte[n]	signature blob in format specific encoding.

	The "ssh-dss" key format has the following specific encoding:

		string	"ssh-dss"
		mpint	p
		mpint	q
		mpint	g
		mpint	y

	Here, the 'p', 'q', 'g', and 'y' parameters form the signature key
	blob.

	Signing and verifying using this key format is done according to the
	Digital Signature Standard [FIPS-186-2] using the SHA-1 hash
	[FIPS-180-2].

	The resulting signature is encoded as follows:

		string	"ssh-dss"
		string	dss_signature_blob

	The value for 'dss_signature_blob' is encoded as a string containing
	r, followed by s (which are 160-bit integers, without lengths or
	padding, unsigned, and in network byte order).

	The "ssh-rsa" key format has the following specific encoding:

		string	"ssh-rsa"
		mpint	e
		mpint	n

	Here the 'e' and 'n' parameters form the signature key blob.

	Signing and verifying using this key format is performed according to
	the RSASSA-PKCS1-v1_5 scheme in [RFC3447] using the SHA-1 hash.

	The resulting signature is encoded as follows:

		string	"ssh-rsa"
		string	rsa_signature_blob

	The value for 'rsa_signature_blob' is encoded as a string containing
	s (which is an integer, without lengths or padding, unsigned, and in
	network byte order).

	The "pgp-sign-rsa" method indicates the certificates, the public key,
	and the signature are in OpenPGP compatible binary format
	([RFC2440]).  This method indicates that the key is an RSA-key.

	The "pgp-sign-dss" is as above, but indicates that the key is a
	DSS-key.
"""


class PublicKeyHandler(GenericHandler):
	
	def __init__(self, alg):
		self.key = None
		self.key_b = None
		self.set_algorithm(alg)


	def set_algorithm(self, alg):
		alg = self.algorithms.get(alg, None)
		if alg is None:
			raise Exception("algorithm not handled")

		available = alg.get("available")
		if not available:
			raise Exception("algorithm not available")

		self.signature_format_identifier = alg
		self.read_method = alg["read_method"]
		self.sign_method = alg["sign_method"]


	def read_key(self, filename):
		self.read_method(self, filename)

	def sign(self, data):
		sig_blob = self.sign_method(self, data)
		return sig_blob


	##############
	# Algorithms #
	##############
	def read_ssh_dss(self, filename):
		self.key = DSA.import_key(open(filename).read())
	
		w = WriteHelper()
		w.write_string("ssh-dss")
		w.write_mpint(self.key.p)
		w.write_mpint(self.key.q)
		w.write_mpint(self.key.g)
		w.write_mpint(self.key.y)

		self.key_b = w.data
	
	def sign_ssh_dss(self, data):
		...
		w = WriteHelper()
		w.write_string("ssh-dss")
		w.write_fixed_int(sig.r, 160)
		w.write_fixed_int(sig.s, 160)
		return w.data


	def read_ssh_rsa(self, filename):
		self.key = RSA.import_key(open(filename).read())

		w = WriteHelper()
		w.write_string("ssh-rsa")
		w.write_mpint(self.key.e)
		w.write_mpint(self.key.n)
		
		self.key_b = w.data
	
	def sign_ssh_rsa(self, data):
		h = SHA1.new(data)
		sig = pkcs1_15.new(self.key).sign(h)
		
		w = WriteHelper()
		w.write_string("ssh-rsa")
		w.write_uint32(len(sig))
		w.write_bytes(sig)
		return w.data


	def read_pgp_sign_rsa(self, filename):
		...
	def sign_pgp_sign_rsa(self, data):
		...


	def read_pgp_sign_dss(self, filename):
		...
	def sign_pgp_sign_dss(self, data):
		...



# List of algorithms and ref of their methods
# Higher prio = first
PublicKeyHandler.algorithms = {
	"ssh-dss": {
		"available": False,
		"priority": -1000,
		"read_method": PublicKeyHandler.read_ssh_dss,
		"sign_method": PublicKeyHandler.sign_ssh_dss},
	"ssh-rsa": {
		"available": True,
		"priority": 1000,
		"read_method": PublicKeyHandler.read_ssh_rsa,
		"sign_method": PublicKeyHandler.sign_ssh_rsa},
	"pgp-sign-rsa": {
		"available": False,
		"priority": 0,
		"read_method": PublicKeyHandler.read_pgp_sign_rsa,
		"sign_method": PublicKeyHandler.read_pgp_sign_rsa},
	"pgp-sign-dss": {
		"available": False,
		"priority": 0,
		"read_method": PublicKeyHandler.read_pgp_sign_dss,
		"sign_method": PublicKeyHandler.read_pgp_sign_dss}
}