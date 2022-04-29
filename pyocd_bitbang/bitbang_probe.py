# -*- coding: utf-8 -*-
#
# Copyright © 2020 NXP
# Copyright © 2020-2021 Chris Reed
# Copyright © 2022 IDEX Biometrics
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# o Redistributions of source code must retain the above copyright notice, this list
#   of conditions and the following disclaimer.
#
# o Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
# o Neither the names of the copyright holders nor the names of the
#   contributors may be used to endorse or promote products derived from this
#   software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import logging
import socket
from time import sleep
from typing import Collection

from pyocd.probe.debug_probe import DebugProbe
from pyocd.core.plugin import Plugin
from pyocd.core import exceptions
from pyocd.utility.mask import parity32_high

from ._version import version as plugin_version

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.disabled = True


class BitBanger():
    """@brief Communicates with the remote TCP server.

    This class implements a remote bitbang interface that drives the SWD pins by sending a series
    of characters over a TCP socket.  The inspiration for this comes from the OpenOCD remote bitbang
    JTAG driver detailed here:
    https://github.com/openocd-org/openocd/blob/master/doc/manual/jtag/drivers/remote_bitbang.txt


    This SWD version re-uses the same character encoding for the Write command but instead of driving
    the {tck, tms, tdi} pins, it drives {swclk, swdoen, swdo}.  Similarly, for the Read command, swdi
    is read rather than tdo.

    Encoding 

    B - Blink on
    b - Blink off
    R - Read request
    Q - quit
    0 - Write 0 0 0
    1 - Write 0 0 1
    2 - Write 0 1 0
    3 - Write 0 1 1
    4 - Write 1 0 0
    5 - Write 1 0 1
    6 - Write 1 1 0
    7 - Write 1 1 1
    r - Reset 0 0
    s - Reset 0 1
    t - Reset 1 0
    u - Reset 1 1

    Note that because the swclk is being bitbanged, driving a '1' or '0' on the bus means we 
    have to send two characters for the posedge and negedge of the clock.

    """

    DEFAULT_PORT = 5555

    ZERO  = b'62'
    ONE   = b'73'
    READ  = b'40R'

    BUFFER_SIZE = 512

    def __init__(self, hostname, port):
        self._hostname = hostname
        self._port = port
        # TCP socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Receive buffer
        self._buf = bytearray()

    def open(self):
        try:
            self._sock.connect((self._hostname,self._port))
        except Exception as e:
            LOG.error(f"socket connect() failed when using {self._hostname}:{self._port}")
            raise e

    def close(self):
        self._sock.close()

    def connect(self):
        pass

    def disconnect(self):
        pass

    def read_bits(self, bits: int) -> int:
        # Send a request to read 'bits' characters
        for bit in range(bits):
            for ch in [bytes([b]) for b in self.READ]:
                self._sock.send(ch)
        # Read the socket until we have received 'bits' bytes
        received = 0
        while received < bits:
            recv = self._sock.recv(self.BUFFER_SIZE)
            self._buf.extend(recv)
            received += len(recv)
        # Take a 'bits' length slice out of the buffer
        value = self._buf[:bits]
        self._buf = self._buf[bits:]
        # Convert to an int and bit reverse (data received lsb first)
        return self._bit_reverse(value, bits)

    def write_bits(self, data: int, bits: int):
        """@brief Write a series of bits to the remote, lsb first. """
        for i in range(bits):
            bit = (data >> i) & 0x1
            self._write_bit(bit)

    def _write_bit(self, bit: int):
        chars = self.ONE if bit else self.ZERO
        for ch in [bytes([b]) for b in chars]:
            if self._sock.send(ch) == 0:
                raise Exception("sock.send() returned 0, closed.")

    def _bit_reverse(self, value, bits):
        return int('{:0{width}b}'.format(int(value,2),width=bits)[::-1],2)


class RemoteBitbangProbe(DebugProbe):
    """@brief Provides a remote TCP bitbang probe. """

    # Address of read buffer register in DP.
    RDBUFF = 0xC

    # SWD command format
    SWD_CMD_START  = (1 << 0)    # always set
    SWD_CMD_APnDP  = (1 << 1)    # set only for AP access
    SWD_CMD_RnW    = (1 << 2)    # set only for read access
    SWD_CMD_A32    = (3 << 3)    # bits A[3:2] of register addr
    SWD_CMD_PARITY = (1 << 5)    # parity of APnDP|RnW|A32
    SWD_CMD_STOP   = (0 << 6)    # always clear for synch SWD
    SWD_CMD_PARK   = (1 << 7)    # driven high by host

    # APnDP constants.
    DP = 0
    AP = 1

    # Read and write constants.
    READ  = 1
    WRITE = 0

    # ACK values
    ACK_OK    = 0b001
    ACK_WAIT  = 0b010
    ACK_FAULT = 0b100
    ACK_ALL   = ACK_FAULT | ACK_WAIT | ACK_OK

    ACK_EXCEPTIONS = {
        ACK_OK: None,
        ACK_WAIT: exceptions.TransferTimeoutError("RemoteBitbangProbe: ACK WAIT received"),
        ACK_FAULT: exceptions.TransferFaultError("RemoteBitbangProbe: ACK FAULT received"),
        ACK_ALL: exceptions.TransferError("RemoteBitbangProbe: Protocol fault"),
    }

    PARITY_BIT = 0x100000000

    @classmethod
    def _extract_address(cls, unique_id):
        parts = unique_id.split(':', 1)
        if len(parts) == 1:
            port = cls.DEFAULT_PORT
        else:
            port = int(parts[1])
        return parts[0], port

    @classmethod
    def get_all_connected_probes(cls, unique_id=None, is_explicit=False):
        if is_explicit and unique_id is not None:
            return [cls(unique_id)]
        else:
            return []

    @classmethod
    def get_probe_with_id(cls, unique_id, is_explicit=False):
        return cls(unique_id) if is_explicit else None

    def __init__(self, unique_id):
        hostname,port = self._extract_address(unique_id)
        self._uid = f"remote_bitbang:{hostname}{port}"
        self._bitbanger = BitBanger(hostname,port)
        self._open = False
        self._retries = 5
        super().__init__()

    @property
    def description(self) -> str:
        return "A remote bitbang probe"

    @property
    def vendor_name(self):
        return "pyOCD"

    @property
    def product_name(self):
        return "remote_bitbang"

    @property
    def supported_wire_protocols(self):
        return [
            self.Protocol.DEFAULT,
            self.Protocol.SWD
        ]

    @property
    def unique_id(self):
        return self._uid

    @property
    def wire_protocol(self):
        return DebugProbe.Protocol.SWD # Could support both SWD and JTAG bitbang in future

    @property
    def is_open(self):
        return self._open

    @property
    def capabilities(self):
        return {
            self.Capability.SWJ_SEQUENCE,
        }

    def open(self):
        self._bitbanger.open()
        self._open = True

    def close(self):
        self._bitbanger.close()
        self._open = False

    # --------------------------------------------------------------------------------
    # Target control
    # --------------------------------------------------------------------------------

    def connect(self):
        self._bitbanger.connect()

    def disconnect(self):
        self._bitbanger.disconnect()

    def set_clock(self, frequency):
        pass

    def swj_sequence(self, length, bits):
        self._bitbanger.write_bits(bits, length)

    # --------------------------------------------------------------------------------
    # DAP access
    # --------------------------------------------------------------------------------

    def read_dp(self, addr, now=True):
        value = self._read_reg(addr, self.DP)

        def callback():
            return value

        return value if now else callback

    def write_dp(self, addr, value):
        self._write_reg(addr, value, self.DP)

    def read_ap(self, addr, now=True):
        (value,) = self.read_ap_multiple(addr)

        def callback():
            return value

        return value if now else callback

    def write_ap(self, addr, value):
        self.write_ap_multiple(addr, (value,))

    def read_ap_multiple(self, addr, count=1, now=True):
        # Send a read request for the AP, discard the stale result
        self._read_reg(addr, self.AP)
        # Read count - 1 new values
        results = [ self._read_reg(addr, self.AP) for n in range(count - 1) ]
        # and read the last result from the RDBUFF register
        results.append(self.read_dp(self.RDBUFF))

        def read_ap_multiple_result_callback():
            return results

        return results if now else read_ap_multiple_result_callback

    def write_ap_multiple(self, addr, values):
        for val in values:
            self._write_reg(addr, val, self.AP)


    # --------------------------------------------------------------------------------
    # Internal functions
    # --------------------------------------------------------------------------------

    def _read_reg(self, addr, APnDP):
        retry = 0
        while True:
            try:
                # Send the SWD command and check the acks
                self._swd_command(self.READ, APnDP, addr)
                break
            except exceptions.TransferTimeoutError as e:
                # Received a WAIT response so transfer the data phase and retry
                self._bitbanger.read_bits(32 + 1 + 1)
                retry += 1
                if retry == self._retries:
                    raise e

        # Read the data + Parity + Trn
        data = self._bitbanger.read_bits(32 + 1 + 1)
        # Insert some idle cycles
        self._bitbanger.write_bits(0,5)
        # Discard the turnaround bit
        val = data & 0xFFFFFFFF
        # Check the parity
        par = data & self.PARITY_BIT
        if par != parity32_high(val):
            raise exceptions.ProbeError('Bad parity in SWD read')
        return val

    def _write_reg(self, addr, value, APnDP):
        retry = 0
        while True:
            try:
                # Send the SWD command and check the acks
                self._swd_command(self.WRITE, APnDP, addr)
                break
            except exceptions.TransferTimeoutError as e:
                # Received a WAIT response so transfer the data phase and retry
                self._bitbanger.write_bits(0, 32 + 1 + 3)
                retry += 1
                if retry == self._retries:
                    raise e

        # Calculate the parity
        value |= parity32_high(value)
        # Send the data + 3 idle cycles
        self._bitbanger.write_bits(value, 32 + 1 + 3)

    def _swd_command(self, RnW, APnDP, addr):
        cmd = (APnDP << 1) + (RnW << 2) + ((addr << 1) & self.SWD_CMD_A32)
        cmd |= parity32_high(cmd) >> (32 - 5)
        cmd |= self.SWD_CMD_START | self.SWD_CMD_STOP | self.SWD_CMD_PARK
        # Write the command to the probe
        self._bitbanger.write_bits(cmd, 8)
        # Read the resulting ACK including turnaround cycles
        data = self._bitbanger.read_bits(1 + 3 + 1 - RnW)
        ack = (data >> 1) & self.ACK_ALL
        # Check for any non OK acks
        if (ack in (self.ACK_FAULT, self.ACK_WAIT)):
            raise self.ACK_EXCEPTIONS[ack]


class RemoteBitbangProbePlugin(Plugin):
    """! @brief Plugin class for RemoteBitbangProbe."""

    def load(self):
        return RemoteBitbangProbe

    @property
    def name(self):
        return "remote_bitbang"

    @property
    def description(self):
        return "remote bitgang debug probe"

    @property
    def version(self):
        return plugin_version

