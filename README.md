# CustomSSH
The intent of this project is to have something that masks itself as an SSH server, but can actually be anything.


## Setup
Start a virtual environment [optional]
```sh
python -m venv ./venv
```

Install requirements
```sh
pip install -r requirements.txt
```


## Tests
To run all tests and generate a coverage report, run
```sh
coverage run -m unittest
coverage html
```

To run a single test module, run
```sh
coverage run -m unittest test.test_TESTMODULE
```

To run a single test case, run
```sh
coverage run -m unittest test.test_TESTMODULE.Test_CLASS
coverage run -m unittest test.test_TESTMODULE.Test_CLASS.test_METHOD
```



## Extra docs
[SEC1](https://www.secg.org/sec1-v2.pdf)


## Method
When connection established, both sides exchange identification strings (RFC4253, 4.2)
Immediately after, key exchange begins.


## Notes
Currently only certain easy to implement algorithms are available. To get the ssh client to use these, use
```sh
ssh -vv -p 2222 user@127.0.0.1 -oKexAlgorithms=diffie-hellman-group14-sha1 -oCiphers=aes128-cbc
```




## TODO
- Add rfc5656 to docs
- Implement https://www.rfc-editor.org/rfc/rfc9142.html
- Add more key exchange methods https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.5
- Read https://datatracker.ietf.org/doc/html/rfc4253
- Test tcpdump when SSHing into something
- Implement Elliptic Curve Diffie Hellman
	- https://datatracker.ietf.org/doc/html/rfc5656#ref-SEC1
	- https://stackoverflow.com/questions/64425381/how-to-generate-a-dh-shared-key-if-the-peer-public-key-is-not-encoded-as-the-hos
	- https://stackoverflow.com/questions/59525079/python-create-ecc-keys-from-private-and-public-key-represented-in-raw-bytes
	- https://www.secg.org/sec1-v2.pdf
	- https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
	- https://pycryptodome.readthedocs.io/_/downloads/en/v3.6.1/pdf/
	- https://github.com/pyca/cryptography/issues/2346
	- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
	- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.Encoding.Raw
	- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/?highlight=x25519#cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey