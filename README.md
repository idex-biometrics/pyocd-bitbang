# pyOCD RemoteBitbang DebugProbe plugin

This pyOCD plugin provides a debug probe that allows connection to a remote bitbang interface
via a TCP socket.  It is design to be used with targets running in simulation.  The remote
end must provide a TCP server that accepts a socket connection.  The debug probe sends an ASCII
encoding of the bitbang interface.

## Installation

```
$ pip install pyocd-bitbang
```

## Background

This plugin is designed to be used to connect, via SWD, to a Verilator model of a Cortex-M based MCU.
This is the pyOCD equivalent to the OpenOCD JTAG remote_bitbang interface, and in fact, uses the same
ASCII encoding.

## Implementation Detail

### DebugProbe

The class `bitbang_probe:RemoteBitbangProbe` implements the minimum subset required by the
pyOCD `pyocd.probe.debug_probe:DebugProbe` class.  Any SWD commands are translated to a series of
read and write calls that drive the remote SWD interface via a TCP socket.  The protocol used is the
same as defined in the OpenOCD [remote_bitbang](https://github.com/openocd-org/openocd/blob/master/doc/manual/jtag/drivers/remote_bitbang.txt) specification.  Each character sent over the socket corresponds to a request
to set the bus to a particular state or to read the value currently being driven on SWDI.

Unlike debug probes connected via USB, pyOCD cannot auto-detect the probe.  Instead, a unique ID must be
specified when launching pyOCD that specifies the probe to use and the IP address and port to use.  See below.

### TCP Server and SV DPI

In addition to this plugin, the testbench must implement a TCP server to which the probe connects as well
as a DPI interface that drives the SWD pins of the DUT.  A good example of such an implementation can be
found in the OpenTitan repository [here](https://github.com/lowRISC/opentitan/tree/master/hw/dv/dpi/jtagdpi).

Modifying the above example to drive a SWD interface is fairly simple.  Instead of the 3 bit Write encoding
driving {tck, tms, tdi}, they should drive {swclk, swdoen, swdo}.

The following snippet shows the character decoding in the main loop of the DPI C function:

```c
  // parse received command byte
  if (cmd >= '0' && cmd <= '7') {
    char cmd_bit = cmd - '0';
    ctx->swclk  = (cmd_bit >> 2) & 0x1;
    ctx->swdoen = (cmd_bit >> 1) & 0x1;
    ctx->swdo   = (cmd_bit >> 0) & 0x1;
  } else if (cmd == 'R') {
    act_send_resp = true;
  } else if (cmd == 'Q') {
    act_quit = true;
  } else {
    fprintf(stderr,
      "SWD DPI Protocol violation detected: unsupported command '%c'\n", cmd);
    exit(1);
  }
```

Inside the `remote_bitbang:BitBanger` class the character encoding for writing a zero or one
on the bus as well as a read is defined:

```python
    ZERO  = b'62'
    ONE   = b'73'
    READ  = b'40R'
```

## Usage

Assuming you have pip installed the pluggin, you should be able to connect to the target using:

```
$ pyocd commander -u remote_bitbang:localhost:5555
```

which would connect to TCP port 5555 on localhost.  No further configuration is necessary.