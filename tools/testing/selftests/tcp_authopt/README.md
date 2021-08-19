# Test linux rfc5925 TCP Authentication Option

Test suite is written in python3 using pytest and scapy. The test suite is
mostly self-contained as a python package.

The recommended way to run this is the included `run.sh` script as root.. It
will automatically create a virtual environment with the correct dependencies
using `tox`.

An old separate version can be found here: https://github.com/cdleonard/tcp-authopt-test
