"""
Public key algorithms
"""
from collections import OrderedDict


def pk_ssh_des():
	"""
	REQUIRED
	sign
	Raw DSS Key
	"""
	...

def pk_ssh_rsa():
	"""
	RECOMMENDED
	sign
	Raw RSA Key
	"""
	...

def pk_pgp_sign_rsa():
	"""
	OPTIONAL
	sign
	OpenPGP certificates (RSA key)
	"""
	...

def pk_pgp_sign_dss():
	"""
	OPTIONAL
	sign
	OpenPGP certificates (DSS key)
	"""
	...


# List of algorithms, in order of priority.
algorithms = OrderedDict({
	"test_pk": None,
	"ecdsa-sha2-nistp256-cert-v01@openssh.com": None,
	# "ssh-dss": pk_ssh_des,
	# "ssh-rsa": pk_ssh_rsa,
	# "pgp-sign-rsa": pk_pgp_sign_rsa,
	# "pgp-sign-dss": pk_pgp_sign_dss,
})
