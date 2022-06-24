
class Config:
	# Can be multiple lines. Each line MUST NOT start with SSH
	IDENTIFICATION_COMMENTS = ["Hello, World!\r\n"]

	# Our server's identification string
	IDENTIFICATION_STRING = "SSH-2.0-CustomSSH_0.1.0 Custom SSH server\r\n"

	LANGUAGES = [] # Only specify if needed. May be ignored by the client
