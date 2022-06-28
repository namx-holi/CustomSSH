
class Config:
	# Can be multiple lines. Each line MUST NOT start with SSH
	IDENTIFICATION_BANNER = ["Hello, World!"]

	# Our server's identification string
	IDENTIFICATION_STRING = "SSH-2.0-CustomSSH_0.1.0 Custom SSH server"

	# Our RSA private key file
	HOST_KEYS = {
		"ssh-rsa": "rsa_key.priv"
	}

	# Successful password when logging in with such
	AUTH_REQUIRED = False
	PASSWORD = "password"

	# Sent at any point during user auth. This can be used to set up a
	#  game to guess the password.
	USERAUTH_BANNER = f"Bro the password its '{PASSWORD}'\n"

