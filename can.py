#
# Copyright (C) 2015 Zubax Robotics <info@zubax.com>
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program.
# If not, see <http://www.gnu.org/licenses/>.
#
# Author: Pavel Kirienko <pavel.kirienko@zubax.com>
#

"""
Simple wrapper over SocketCAN and an SLCAN driver.
Requires Python 3.4 or newer.
"""

import binascii
import struct
import select
import time
import re
from logging import getLogger


logger = getLogger(__name__)


STD_ID_MASK = 0x000007FF
EXT_ID_MASK = 0x1FFFFFFF
MAX_LEN = 8


class CANDriverException(Exception):
    pass


class TimeoutException(CANDriverException, TimeoutError):
    pass


# noinspection PyShadowingBuiltins
class SocketCAN:
    FORMAT = '=IB3x8s'
    IO_SIZE = 16
    EXT_ID_FLAG = 1 << 31

    @staticmethod
    def _parse_frame(frame):
        id, can_dlc, data = struct.unpack(SocketCAN.FORMAT, frame)  # @ReservedAssignment
        ext = bool(id & SocketCAN.EXT_ID_FLAG)
        return {
            'id': id & EXT_ID_MASK,
            'data': data[:can_dlc],
            'ext': ext
        }

    @staticmethod
    def _make_frame(id, data, ext):  # @ReservedAssignment
        if isinstance(data, str):
            data = bytes(data, 'utf8')

        if not isinstance(data, bytes):
            data = bytes(data)

        assert id & (EXT_ID_MASK if ext else STD_ID_MASK) == id
        assert len(data) <= MAX_LEN

        if ext:
            id |= SocketCAN.EXT_ID_FLAG

        can_dlc = len(data)
        data = data.ljust(MAX_LEN, b'\x00')
        return struct.pack(SocketCAN.FORMAT, id, can_dlc, data)

    def __init__(self, iface_name, default_timeout=None):
        import socket
        self.default_timeout = default_timeout

        self.socket = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.socket.bind((iface_name,))

        self.poll = select.poll()
        self.poll.register(self.socket.fileno())

    def _resolve_timeout_ms(self, timeout):
        if timeout is not None:
            return timeout * 1000

        if self.default_timeout is not None:
            return self.default_timeout * 1000

    def receive(self, timeout=None):
        self.poll.modify(self.socket.fileno(), select.POLLIN | select.POLLPRI)
        out = self.poll.poll(self._resolve_timeout_ms(timeout))
        if not len(out):
            raise TimeoutException('CAN bus read timeout')

        frame, (_iface, _id_size) = self.socket.recvfrom(self.IO_SIZE)
        return self._parse_frame(frame)

    def _send_impl(self, encoded_frame, timeout):
        self.poll.modify(self.socket.fileno(), select.POLLOUT)
        out = self.poll.poll(self._resolve_timeout_ms(timeout))
        if not len(out):
            raise TimeoutException('CAN bus write timeout')

        self.socket.send(encoded_frame)

    def send_std(self, id, data, timeout=None):  # @ReservedAssignment
        self._send_impl(self._make_frame(id, data, False), timeout)

    def send_ext(self, id, data, timeout=None):  # @ReservedAssignment
        self._send_impl(self._make_frame(id, data, True), timeout)

    def close(self):
        self.socket.close()


# noinspection PyPep8Naming
def Bus(*args, **kwargs):
    from warnings import warn
    warn('Class Bus is deprecated, use SocketCAN instead')
    return SocketCAN(*args, **kwargs)


# noinspection PyShadowingBuiltins,PyBroadException
class SLCAN:
    """
    A basic SLCAN adapter driver.
    This class is only suitable for very simple, low-traffic applications.
    For a full-featured SLCAN driver, optimized for high-traffic applications,
    with timestamp recovery etc, please refer to the PyUAVCAN library.
    """

    ACK = b'\r'
    NAK = b'\a'
    CLI_END_OF_LINE = b'\r\n'
    CLI_END_OF_TEXT = b'\x03'

    def _write(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.port.write(data)

    def _read_packet(self, timeout):
        out = bytes()
        self.port.timeout = timeout
        while True:
            b = self.port.read()
            if not b:
                raise TimeoutException('SLCAN port read timeout')
            out += b
            if b in (self.ACK, self.NAK):
                break
        return out

    def _execute_slcan_command(self, command, timeout=1):
        if isinstance(command, str):
            command = command.encode()
        self._write(command + self.ACK)
        self.port.flush()
        response = self._read_packet(timeout)
        if self.NAK in response:
            raise CANDriverException('NAK in response: %r -> %r', command, response)
        return response

    def _init(self, bitrate):
        try:
            speed_code = {
                1000000: 8,
                800000:  7,
                500000:  6,
                250000:  5,
                125000:  4,
                100000:  3,
                50000:   2,
                20000:   1,
                10000:   0
            }[bitrate]
        except KeyError:
            raise CANDriverException('Unsupported CAN bitrate: %r' % bitrate)

        # Sending an empty command in order to reset the adapter's command parser, then discarding all output
        try:
            self._execute_slcan_command('')
        except CANDriverException:
            pass
        self.port.flushInput()

        # Making sure the channel is closed - some adapters may refuse to re-open if the channel is already open
        try:
            self._execute_slcan_command('C')
        except CANDriverException:
            pass

        # Setting speed code
        self._execute_slcan_command('S%d' % speed_code)

        # Opening the channel
        self._execute_slcan_command('O')

        # Clearing error flags
        try:
            self._execute_slcan_command('F')
        except CANDriverException as ex:
            logger.info('SLCAN: Could not clear error flags (command not supported by the CAN adapter?): %s', ex)

    def __init__(self, port, bitrate, baudrate=115200, default_timeout=None):
        import serial
        self.port = serial.Serial(port, baudrate=baudrate)
        self.default_timeout = default_timeout

        remaining_attempts = 3
        while True:
            remaining_attempts -= 1
            # noinspection PyBroadException
            try:
                self._init(bitrate)
            except Exception:
                if remaining_attempts >= 0:
                    logger.error('SLCAN init failed, will retry', exc_info=True)
                else:
                    raise
            else:
                break

        # Discarding all output again
        time.sleep(0.1)
        self.port.flushInput()

        logger.debug('SLCAN init OK; %d unused attempts', remaining_attempts)

    def __del__(self):
        logger.info('SLCAN: closing on delete')
        try:
            self._execute_slcan_command('C')
        except Exception:
            logger.error('SLCAN could not be closed, error ignored', exc_info=True)

    def close(self):
        try:
            self._execute_slcan_command('C')
        except Exception:
            logger.error('SLCAN could not be closed, error ignored', exc_info=True)

    def _resolve_timeout(self, timeout):
        return timeout if timeout is not None else self.default_timeout  # Which also may be None

    def _process_slcan_line(self, line):
        # This function was taken from the PyUAVCAN SLCAN driver
        line = line.strip().strip(self.NAK).strip(self.CLI_END_OF_TEXT)

        if len(line) < 1:
            return

        # Checking the header, ignore all irrelevant lines
        if line[0] == b'T'[0]:
            id_len = 8
        elif line[0] == b't'[0]:
            id_len = 3
        else:
            return

        # Parsing ID and DLC
        packet_id = int(line[1:1 + id_len], 16)
        packet_len = line[1 + id_len] - 48

        if packet_len > 8 or packet_len < 0:
            raise CANDriverException('SLCAN: Invalid packet length [%d]' % packet_len)

        packet_data = binascii.a2b_hex(line[2 + id_len:2 + id_len + packet_len * 2])

        # Timestamp ignored (PyUAVCAN does correctly parse timestamps and syncs clocks using the Olson algorithm)
        return {
            'id': packet_id,
            'data': packet_data,
            'ext': id_len == 8
        }

    def receive(self, timeout=None):
        while True:
            packet = self._read_packet(self._resolve_timeout(timeout))
            try:
                frame = self._process_slcan_line(packet)
                if frame:
                    return frame
            except Exception:
                logger.warning('SLCAN packet parsing error; packet: %r', packet, exc_info=True)

    def send(self, id, data, extended, timeout=None):  # @ReservedAssignment
        self.port.writeTimeout = self._resolve_timeout(timeout)
        line = '%s%d%s\r' % (('T%08X' if extended else 't%03X') % id, len(data), binascii.b2a_hex(data).decode('ascii'))
        self.port.write(line.encode('ascii'))
        self.port.flush()

    def send_std(self, id, data, timeout=None):  # @ReservedAssignment
        self.send(id, data, False, timeout)

    def send_ext(self, id, data, timeout=None):  # @ReservedAssignment
        self.send(id, data, True, timeout)

    def execute_cli_command(self, command, timeout=None):
        # While the command is being executed, incoming frames will be lost.
        # SLCAN driver from PyUAVCAN goes at great lengths to properly separate CLI response lines
        # from SLCAN messages in real time with minimal additional latency, so use it if you care about this.
        timeout = self._resolve_timeout(timeout)
        self.port.writeTimeout = timeout
        command += '\r\n'
        self._write(command)

        deadline = time.monotonic() + (timeout if timeout is not None else 999999999)
        self.port.timeout = 1
        response = bytes()

        while True:
            if time.monotonic() > deadline:
                raise TimeoutException('SLCAN CLI response timeout; command: %r' % command)

            b = self.port.read()
            if b == self.CLI_END_OF_TEXT:
                break
            if b:
                response += b

        # Removing SLCAN lines from response
        return re.sub(r'.*\r[^\n]', '', response.decode()).strip().replace(command, '')


if __name__ == '__main__':
    import sys
    import logging
    import glob

    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

    drv = SLCAN(glob.glob('/dev/serial/by-id/*Zubax_Babel*')[0], 1000000)

    print(drv.execute_cli_command('zubax_id', 1))
    print(drv.execute_cli_command('stat'))

    r = None
    while True:
        try:
            r = drv.receive(1)
            print(r)
        except TimeoutException:
            pass
        if r:
            (drv.send_ext if r['ext'] else drv.send_std)(r['id'], r['data'])
