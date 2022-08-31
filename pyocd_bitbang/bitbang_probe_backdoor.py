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
import struct
from time import sleep
from typing import (Callable, Sequence, Union)

from pyocd.core.plugin import Plugin
from pyocd.core import exceptions
from pyocd.core.memory_interface import MemoryInterface
from pyocd.utility import conversion

from ._version import version as plugin_version
from .bitbang_probe import RemoteBitbangProbe

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.disabled = True

class BackdoorMemoryInterface(MemoryInterface):
    """@brief A backdoor memory interface for use with a simulation model. 
    
    Each read/write request has two phases, a header and a payload.  The header defines
    the transaction and should match the C struct as defined by:

    struct __attribute__ ((__packed__)) Request {
      unsigned int   address;
      unsigned short size;
      unsigned char  rnw;
    };

    where the fields are defined as follows:

      address : the byte address of the access
      size    : the number of bytes to write or read
      rnw     : read-not-write bit (read = 1)

    A write access comprises the header, the data payload and an acknowledge byte.

    A read access comprises the header and a data payload only.
    
    """

    WRITE = 0x0
    READ  = 0x1
    ACK   = 0x15

    def __init__(self, hostname:str, port:int) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._sock.connect((hostname, port))
            LOG.debug(f"connected to {hostname}:{port}")
        except Exception as e:
            LOG.error(f"socket connect() failed when using {hostname}:{port}")
            raise e

    def close(self):
        self._sock.close()

    def write_memory(self, addr: int, data: int, transfer_size: int = 32, **kwargs) -> None:
        """@brief Write a single memory location. """
        assert transfer_size in (8, 16, 32)
        addr &= 0xffffffff
        if transfer_size == 32:
            self._write_mem8(addr, conversion.u32le_list_to_byte_list([data]))
        elif transfer_size == 16:
            self._write_mem8(addr, conversion.u16le_list_to_byte_list([data]))
        elif transfer_size == 8:
            self._write_mem8(addr, [data])

    def read_memory(self, addr: int, transfer_size: int = 32, now: bool = True, **kwargs) -> Union[int, Callable[[], int]]:
        """@brief Read a single memory location. """
        assert transfer_size in (8, 16, 32)
        addr &= 0xffffffff
        if transfer_size == 32:
            result = conversion.byte_list_to_u32le_list(self._read_mem8(addr, 4))[0]
        elif transfer_size == 16:
            result = conversion.byte_list_to_u16le_list(self._read_mem8(addr, 2))[0]
        elif transfer_size == 8:
            result = self._read_mem8(addr, 1)[0]

        def read_callback():
            return result
        return result if now else read_callback

    def write_memory_block32(self, addr: int, data: Sequence[int]) -> None:
        """@brief Write an aligned block of 32-bit words."""
        self._write_mem8(addr, conversion.u32le_list_to_byte_list(data))

    def read_memory_block32(self, addr: int, size: int) -> Sequence[int]:
        """@brief Read an aligned block of 32-bit words."""
        return conversion.byte_list_to_u32le_list(self._read_mem8(addr, size*4))

    def _write_mem8(self, addr: int, data: Sequence[int]):
        assert isinstance(data, Sequence), "`data` must be byte Sequence"
        self._send_header(addr, len(data), self.WRITE)
        self._send_payload(bytearray(data))

    def _read_mem8(self, addr: int, size: int) -> Sequence[int]:
        self._send_header(addr, size, self.READ)
        return self._recv_payload(size)

    def _send_header(self, addr: int, size: int, rnw: int) -> None:
        header = (addr, size, rnw)
        self._sock.sendall(struct.pack('I H B', *header))

    def _send_payload(self, bytes: bytearray):
        self._sock.sendall(bytes)
        self._recv_ack()

    def _recv_payload(self, size: int) -> Sequence[int]:
        return self._recv_bytes(size)

    def _recv_ack(self) -> None:
        ack = self._recv_bytes(1)[0]
        assert ack == self.ACK, "invalid ACK received, got %s" % ack

    def _recv_bytes(self, size: int) -> Sequence[int]:
        data = bytearray()
        while (len(data) < size):
            n = self._sock.recv(1024)
            data += n
        return list(data)


class RemoteBitbangBackdoorProbe(RemoteBitbangProbe):
    """@brief Extends RemoteBitbangProbe by providing an accelerated memory interface.

    This probe is designed to be used with an ASIC simulation model that implements the required
    memory access methods as defined in BackdoorMemoryInterface.  It is assumed these methods provide
    backdoor access to memories in the design allowing zero time upload and download of data.
    This is useful for fast loading and dumping with GDB that would otherwise take a long time
    over SWD.

    """
    def get_memory_interface_for_ap(self, *args):
        """@brief Returns an accelerated memory interface.
        
        """
        return BackdoorMemoryInterface(self.hostname, self.port+2)


class RemoteBitbangBackdoorProbePlugin(Plugin):
    """! @brief Plugin class for RemoteBitbangBackdoorProbe."""

    def load(self):
        return RemoteBitbangBackdoorProbe

    @property
    def name(self):
        return "remote_bitbang_backdoor"

    @property
    def description(self):
        return "remote bitgang debug probe with backdoor memory access"

    @property
    def version(self):
        return plugin_version

