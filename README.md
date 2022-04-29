pyOCD RemoteBitbang plugin debug probes support
================================================

This pyOCD plugin provides a debug probe that allows connection to a remote bitbang interface
via a TCP socket.  It is design to be used with targets running in simulation.  The remote
end must provide a TCP server that accepts a socket connection.  The debug probe sends an ASCII
encoding of the bitbang interface.

TODO: define the interface

Author: Shareef Jalloq, shareef.jalloq@idexbiometrics.com (IDEX Biometrics 2022, www.idexbiometrics.com)

Note
----
This package is a plugin to the full PyOCD package - it doesn't work standalone!


Dependencies
------------
pyocd
logging
time
socket
threading

Installation
------------
Directly from www.pypi.org:

``` bash
    $ pip install pyocd_bitbang
