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

import sys
assert sys.version[0] == '3'

import requests
import getpass
import json
import os
import base64
import logging
import http.client as http_codes
import colorama
import argparse
import threading
import itertools
import time
import glob
import fnmatch
import contextlib
import tempfile
from functools import partial
try:
    import readline  # @UnusedImport
except ImportError:
    pass


DEFAULT_SERVER = 'licensing.zubax.com'
SUPPORT_EMAIL = 'licensing@zubax.com'
APP_DATA_PATH = os.path.join(os.path.expanduser("~"), '.zubax', 'drwatson')
LOG_FILE_PATH = 'drwatson.log'
REQUEST_TIMEOUT = 20


# Default config - log everything into a file; stderr loggers will be added from init()
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(name)-25s %(message)s')
logging.getLogger('uavcan.dsdl.parser').setLevel(logging.INFO)

logger = logging.getLogger(__name__)
logger.info('STARTED')

colorama.init()

server = DEFAULT_SERVER


class DrwatsonException(Exception):
    pass


class APIException(DrwatsonException):
    pass


class ResponseParams(dict):
    def __init__(self, *args, **kwargs):
        super(ResponseParams, self).__init__(*args, **kwargs)
        self.__dict__ = self

    def _b64_decode_existing_params(self, param_names):
        for p in param_names:
            if p in self:
                self[p] = _b64_decode(self[p])


class APIContext:
    def __init__(self, login, password):
        self.login = login
        self.password = password

    def _call(self, call, **arguments):
        logger.debug('Calling %r with %r', call, arguments)

        endpoint = _make_api_endpoint(self.login, self.password, call)
        if len(arguments):
            data = json.dumps(arguments)
            resp = requests.post(endpoint, data=data, timeout=REQUEST_TIMEOUT)
        else:
            resp = requests.get(endpoint, timeout=REQUEST_TIMEOUT)

        if resp.status_code == http_codes.PAYMENT_REQUIRED:
            raise APIException('PAYMENT REQUIRED [%s]' % resp.text)

        if resp.status_code == http_codes.BAD_REQUEST:
            raise APIException('BAD REQUEST [%s]' % resp.text)

        if resp.status_code != http_codes.OK:
            raise APIException('Unexpected HTTP code: %r [%s]' % (resp, resp.text))

        resp = resp.text
        return resp if not resp else ResponseParams(json.loads(resp))

    def get_balance(self):
        return self._call('balance')

    def generate_signature(self, unique_id, product_name):
        resp = self._call('signature/generate', unique_id=_b64_encode(unique_id), product_name=product_name)
        resp._b64_decode_existing_params(['unique_id', 'signature'])
        return resp

    def verify_signature(self, unique_id, product_name, signature):
        return self._call('signature/verify', unique_id=_b64_encode(unique_id),
                          product_name=product_name, signature=_b64_encode(signature))


def make_api_context_with_user_provided_credentials():
    # Reading login from cache
    login_cache_path = os.path.join(APP_DATA_PATH, 'licensing_login')
    try:
        with open(login_cache_path) as f:
            login = f.read().strip()
    except Exception:
        logger.debug('Could not read login cache', exc_info=True)
        login = None

    # Running in the loop until the user provides valid credentials
    while True:
        try:
            imperative('Enter your credentials for %r', server)

            provided_login = input(('Login [%s]: ' % login) if login else 'Login: ', same_line=True)
            login = provided_login or login

            imperative('Password: ', end='')
            password = getpass.getpass('')
        except KeyboardInterrupt:
            info('Exit')
            exit()

        with CLIWaitCursor():
            try:
                response = requests.get(_make_api_endpoint(login, password, 'balance'), timeout=REQUEST_TIMEOUT)
            except Exception as ex:
                logger.info('Request failed with error: %r', ex, exc_info=True)
                error('Could not reach the server, please check your Internet connection.')
                info('Error info: %r', ex)
                continue

        if response.status_code == http_codes.UNAUTHORIZED:
            info('Incorrect credentials')
        elif response.status_code == http_codes.OK:
            break
        else:
            raise APIException('Unexpected HTTP code: %r' % response)

    if not _ordinary():
        info('We like you')

    # Trying to cache the login
    try:
        try:
            os.makedirs(APP_DATA_PATH, exist_ok=True)
        except Exception:
            logger.debug('Could not create login cache dir', exc_info=True)
        with open(login_cache_path, 'w') as f:
            f.write(login)
    except Exception:
        logger.info('Could not write login cache', exc_info=True)

    # Returning new instance with newly supplied login credentials
    return APIContext(login, password)


def download(url, encoding=None):
    logger.debug('Downloading %r', url)

    def decode(data):
        return data.decode(encoding) if encoding else data

    if '://' in url[:10]:
        r = requests.get(url, stream=True, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            r.raw.decode_content = True
            data = r.raw.read()
            logger.info('Downloaded %d bytes from %r', len(data), url)
            return decode(data)
        raise DrwatsonException('Could not download %r: %r' % (url, r))
    else:
        with open(url, 'rb') as f:
            return decode(f.read())


def download_newest(glob_url, encoding=None):
    try:
        import easywebdav
    except ImportError:
        fatal('Please install the missing dependency: pip3 install easywebdav')

    protocol, _rest = glob_url.split('://', 1)
    domain_name, path_glob = _rest.split('/', 1) if '/' in _rest else (_rest, '')
    path_glob = '/' + path_glob
    directory = path_glob if path_glob.endswith('/') else path_glob.rsplit('/', 1)[0]

    c = easywebdav.connect(domain_name, protocol=protocol)

    matching_item = None
    for item in sorted(c.ls(directory), key=lambda x: x.ctime, reverse=True):
        if item.name.strip('/') == directory.strip('/'):
            continue
        if fnmatch.fnmatch(item.name, path_glob):
            matching_item = item
            break

    if not matching_item:
        raise DrwatsonException('No entry at WebDAV %r', glob_url)

    return download('%s://%s%s' % (protocol, domain_name, matching_item.name), encoding=encoding)


def glob_one(expression):
    res = glob.glob(expression)
    if len(res) == 0:
        raise DrwatsonException('Could not find matching filesystem entry: %r' % expression)
    if len(res) != 1:
        raise DrwatsonException('Expected one filesystem entry, found %d: %r' % (len(res), expression))
    return res[0]


def open_serial_port(port_glob, baudrate=None, timeout=None, use_contextmanager=True):
    try:
        import serial
    except ImportError:
        fatal('Please install the missing dependency: pip3 install pyserial')

    baudrate = baudrate or 115200
    timeout = timeout or 1
    port = glob_one(port_glob)
    logger.debug('Opening serial port %r baudrate %r timeout %r',
                 port, baudrate, timeout)

    # TODO FIXME HACK
    # The line below is not supposed to exist - it is an ugly workaround to some sort of PySerial bug.
    # The problem is that in certain cases certain USB-UART adapters (like DroneCode Probe) do not work
    # (either use incorrect baud rate or read() call blocks forever despite timeout) until this operation
    # is performed on them.
    # Steps to reproduce:
    # 1. Connect DroneCode Probe via USB hub (not sure if hub is involved)
    # 2. Without doing anything with the connected adapter, open serial port using pyserial at 115200 with timeout
    # 3. Call readlines(). The call will either hang forever or return garbage.
    # The problem requires deeper investigation.
    execute_shell_command('stty -F %s %d', port, baudrate)

    ser = serial.Serial(port, baudrate, timeout=timeout)
    if use_contextmanager:
        ser = contextlib.closing(ser)
    return ser


ui_logger = logging.getLogger(__name__ + '_ui')


def _print_impl(logging_header, color, fmt, *args, end='\n'):
    text = fmt % args
    ui_logger.debug(logging_header + '\n' + text)

    sys.stdout.write(colorama.Style.BRIGHT + color)  # @UndefinedVariable
    sys.stdout.write(text)
    if end:
        sys.stdout.write(end)
    sys.stdout.write(colorama.Style.RESET_ALL)  # @UndefinedVariable
    sys.stdout.flush()

imperative = partial(_print_impl, 'IMPERATIVE', colorama.Fore.GREEN)    # @UndefinedVariable
error = partial(_print_impl, 'ERROR', colorama.Fore.RED)                # @UndefinedVariable
warning = partial(_print_impl, 'WARNING', colorama.Fore.YELLOW)         # @UndefinedVariable
info = partial(_print_impl, 'INFO', colorama.Fore.WHITE)                # @UndefinedVariable


_native_input = input


def input(fmt, *args, yes_no=False, default_answer=False, same_line=False):  # @ReservedAssignment
    with CLIWaitCursor.Suppressor():
        text = fmt % args
        ui_logger.debug('INPUT REQUEST\n' + text)
        if yes_no:
            text = text.rstrip() + (' (Y/n)' if default_answer else ' (y/N)')
        if text[-1] not in (' \t\r\n' if same_line else '\r\n'):
            text += ' ' if same_line else '\n'

        out = _native_input(colorama.Style.BRIGHT + colorama.Fore.GREEN +   # @UndefinedVariable
                            text +
                            colorama.Style.RESET_ALL)                       # @UndefinedVariable

        ui_logger.debug('INPUT RESPONSE\n' + out)

        if yes_no:
            if default_answer:
                out = (out[0].lower() != 'n') if out else True
            else:
                out = (out[0].lower() == 'y') if out else False
            info('Answered %s', 'YES' if out else 'NO')
            return out
        else:
            return out


def fatal(fmt, *args, use_abort=False):
    error(fmt, *args)
    if use_abort:
        os.abort()
    else:
        exit(1)


class AbortException(DrwatsonException):
    pass


def abort(fmt, *args):
    raise AbortException(str(fmt) % args)


def enforce(condition, fmt, *args):
    if not condition:
        abort(fmt, *args)


def run(handler):
    while True:
        try:
            print('=' * 80)
            input('Press ENTER to begin, Ctrl+C to exit')

            handler()

            info('COMPLETED SUCCESSFULLY')
        except KeyboardInterrupt:
            logger.debug('KeyboardInterrupt in main loop', exc_info=True)
            info('\nExit')
            break
        except AbortException as ex:
            error('ABORTED: %s', str(ex))
        except Exception as ex:
            logger.info('Main loop error: %r', ex, exc_info=True)
            error('FAILURE: %r', ex)
        finally:
            sys.stdout.write(colorama.Style.RESET_ALL)  # @UndefinedVariable


def execute_shell_command(fmt, *args, ignore_failure=False):
    cmd = fmt % args
    logger.debug('Executing: %r', cmd)
    ret = os.system(cmd)
    if ret != 0:
        msg = 'Command exited with status %d: %r' % (ret, cmd)
        if ignore_failure:
            logger.debug(msg)
        else:
            raise DrwatsonException(msg)
    return ret


def _make_api_endpoint(login, password, call):
    local = server.lower().strip().split(':')[0] in ['0.0.0.0', '127.0.0.1', 'localhost']
    protocol = 'http' if local else 'https'
    endpoint = '%s://%s:%s@%s/api/v1/%s' % (protocol, login, password, server, call)
    if not endpoint.startswith('https'):
        logger.warning('USING INSECURE PROTOCOL')
    return endpoint


def _b64_encode(x):
    if isinstance(x, str):
        x = x.encode('utf8')
    if not isinstance(x, bytes):
        x = bytes(x)
    return base64.b64encode(x).decode()


def _b64_decode(x):
    return base64.b64decode(x, validate=True)


def _ordinary():
    import random
    return random.random() >= 0.01


def init(description, *arg_initializers, require_root=False):
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    for ai in arg_initializers:
        ai(parser)

    parser.add_argument('--verbose', '-v', action='count', default=0, help='verbosity level (-v, -vv)')
    parser.add_argument('--server', '-s', default=DEFAULT_SERVER, help='licensing server')

    args = parser.parse_args()

    global server
    server = args.server

    logging_level = {
        0: logging.WARN,
        1: logging.INFO,
        2: logging.DEBUG
    }.get(args.verbose, logging.DEBUG)

    max_logger_name_len = max(map(len, logging.Logger.manager.loggerDict.keys()))                  # @UndefinedVariable
    formatter = logging.Formatter('{}%(asctime)s %(levelname)-.1s %(name)-{}s{} %(message)s'
                                  .format(colorama.Style.BRIGHT + colorama.Fore.BLUE,              # @UndefinedVariable
                                          max_logger_name_len,
                                          colorama.Style.RESET_ALL),                               # @UndefinedVariable
                                  datefmt='%H:%M:%S')

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging_level)
    handler.setFormatter(formatter)

    logging.root.addHandler(handler)

    if require_root and os.geteuid() != 0:
        fatal('This program requires superuser priveleges')

    info('Color legend:')
    imperative('\tFOLLOW INSTRUCTIONS IN GREEN')
    error('\tERRORS ARE REPORTED IN RED')
    warning('\tWARNINGS ARE REPORTED IN YELLOW')
    info('\tINFO MESSAGES ARE PRINTED IN WHITE')
    info('Press CTRL+C to exit the application. In case of technical difficulties,\n'
         'please send the file %r to %s.', LOG_FILE_PATH, SUPPORT_EMAIL)

    return args


def catch(exception=Exception, return_on_catch=None):
    def decorate(function):
        def wrapper(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except exception:
                return return_on_catch
        return wrapper
    return decorate


class CLIWaitCursor(threading.Thread):
    """Usage:
    with CLIWaitCursor():
        long_operation()
        with CLIWaitCursor.Suppressor():
            input('Input: ')    # No wait cursor here
    """

    SUPPRESSED = 0

    class Suppressor:
        def __enter__(self):
            CLIWaitCursor.SUPPRESSED += 1

        def __exit__(self, _type, _value, _traceback):
            CLIWaitCursor.SUPPRESSED -= 1

    def __init__(self):
        super(CLIWaitCursor, self).__init__(name='wait_cursor_spinner', daemon=True)
        self.spinner = itertools.cycle(['|', '/', '-', '\\'])
        self.keep_going = True

    def __enter__(self):
        self.start()

    def __exit__(self, _type, _value, _traceback):
        self.keep_going = False
        self.join()

    def run(self):
        while self.keep_going:
            if CLIWaitCursor.SUPPRESSED <= 0:
                sys.stdout.write(next(self.spinner) + '\033[1D')
                sys.stdout.flush()
            time.sleep(0.1)


class SerialCLI:
    """This class is designed for interaction with serial port based CLI.
    """

    def __init__(self, serial_port, default_timeout=None):
        self._io = serial_port
        self._echo_bytes = []
        self.default_timeout = default_timeout or 1

    def flush_input(self, delay=None):
        if delay:
            time.sleep(delay)
        self._io.flushInput()

    def write_line(self, fmt, *args):
        bs = ((fmt % args) + '\r\n').encode()
        self._io.write(bs)
        self._echo_bytes += list(bs)

    def read_line(self, timeout=None):
        """Returns a tuple (bool, str). The first item is False if the timeout has expired, otherwise True.
        """
        self._io.timeout = timeout if timeout is not None else self.default_timeout
        out_bytes = []
        timed_out = False
        while True:
            b = self._io.read(1)
            if not b:
                timed_out = True
                break
            b = b[0]
            if self._echo_bytes and b == self._echo_bytes[0]:
                self._echo_bytes.pop(0)
            else:
                out_bytes.append(b)
                if b == b'\n'[0]:
                    break

        return timed_out, bytes(out_bytes).decode('utf8', 'ignore').strip() if out_bytes else None

    def write_line_and_read_output_lines_until_timeout(self, fmt, *args, timeout=None):
        self.write_line(fmt, *args)
        lines = []
        while True:
            to, ln = self.read_line(timeout)
            if to:
                break
            lines.append(ln)
        return lines


class BackgroundSpinner(threading.Thread):
    """This class is designed to make periodic calls to a specified target in the background.
    Usage:

    with BackgroundSpinner(target):
        long_operation()

    If you need to use this class you're probably doing something wrong. ;)
    """

    def __init__(self, target, *args, **kwargs):
        super(BackgroundSpinner, self).__init__(name='background_spinner:' + repr(target), daemon=True)
        self._spin_target = lambda: target(*args, **kwargs)
        self._keep_going = True

    def run(self):
        while self._keep_going:
            try:
                self._spin_target()
            except Exception:
                logger.error('Background spinner error', exc_info=True)

    def __enter__(self):
        logger.debug('Starting BackgroundSpinner [%r]', self)
        self.start()

    def __exit__(self, _type, _value, _traceback):
        logger.debug('Stopping BackgroundSpinner [%r]...', self)
        self._keep_going = False
        self.join()
        logger.debug('BackgroundSpinner [%r] stopped', self)


class BackgroundDelay(threading.Thread):
    """This class will invoke a specified callback from a background thread after the specified timeout expires.
    It is designed for use with a context - the timer will stop automatically once the current context is exited.
    Usage:

    with BackgroundDelay(10, die, 'The operation did not complete in 10 seconds!!'):
        long_operation()
    """

    def __init__(self, delay, target, *args, **kwargs):
        super(BackgroundDelay, self).__init__(name='background_dead_man_switch:' + repr(target), daemon=True)
        self._delay = delay
        self._dms_target = lambda: target(*args, **kwargs)
        self._event = threading.Event()

    def run(self):
        if not self._event.wait(self._delay):
            self._dms_target()

    def __enter__(self):
        logger.debug('Starting BackgroundDelay [%r]', self)
        self.start()

    def __exit__(self, _type, _value, _traceback):
        logger.debug('Stopping BackgroundDelay [%r]...', self)
        self._event.set()
        self.join()
        logger.debug('BackgroundDelay [%r] stopped', self)


def load_firmware_via_gdb(firmware_data,
                          toolchain_prefix,
                          load_offset,
                          gdb_port,
                          gdb_monitor_scan_command):
    with tempfile.TemporaryDirectory('-drwatson') as tmpdir:
        logger.debug('Executable scratchpad directory: %r', tmpdir)
        fn = lambda x: os.path.join(tmpdir, x)
        runtc = lambda fmt, *a, **kw: execute_shell_command(toolchain_prefix + fmt, *a, **kw)

        # Generating ELF from the downloaded binary
        with open(fn('fw.bin'), 'wb') as f:
            f.write(firmware_data)

        with open(fn('link.ld'), 'w') as f:
            f.write('SECTIONS { . = %s; .text : { *(.text) } }' % load_offset)

        runtc('ld -b binary -r -o %s %s', fn('tmp.elf'), fn('fw.bin'))
        runtc('objcopy --rename-section .data=.text --set-section-flags .data=alloc,code,load %s', fn('tmp.elf'))
        runtc('ld %s -T %s -o %s', fn('tmp.elf'), fn('link.ld'), fn('output.elf'))

        # Loading the ELF onto the target
        with open(fn('script.gdb'), 'w') as f:
            f.write('\n'.join([
                'target extended-remote %s' % gdb_port,
                'mon %s' % gdb_monitor_scan_command,
                'attach 1',
                'load',
                'compare-sections',
                'kill',
                'quit 0'
            ]))

        runtc('gdb %s --batch -x %s -return-child-result -silent', fn('output.elf'), fn('script.gdb'))
