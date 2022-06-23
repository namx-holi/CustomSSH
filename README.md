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


## TODO
- Read https://datatracker.ietf.org/doc/html/rfc4253
- Test tcpdump when SSHing into something
