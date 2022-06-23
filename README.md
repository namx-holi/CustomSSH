# CustomSSH
The intent of this project is to have something that masks itself as an SSH server, but can actually be anything.


## Tests
To run a single test module, run
```sh
python -m unittest test.test_TESTMODULE
```

To run a single test case, run
```sh
python -m unittest test.test_TESTMODULE.Test_CLASS
python -m unittest test.test_TESTMODULE.Test_CLASS.test_METHOD
```

To run all tests, run
```sh
python -m unittest
```


## TODO
- Read https://datatracker.ietf.org/doc/html/rfc4253
- Test tcpdump when SSHing into something
