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




## Method
When connection established, both sides exchange identification strings (RFC4253, 4.2)
Immediately after, key exchange begins.


## Notes
Currently only certain easy to implement algorithms are available. To get the ssh client to use these, use
```sh
ssh -vv -p 2222 127.0.0.1 -oKexAlgorithms=diffie-hellman-group14-sha1 -oCiphers=aes128-cbc
```




## TODO
- Implement https://www.rfc-editor.org/rfc/rfc9142.html
- Add more key exchange methods https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.section.3.5
- Read https://datatracker.ietf.org/doc/html/rfc4253
- Test tcpdump when SSHing into something
