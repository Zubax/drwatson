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
from functools import partial
try:
    import readline  # @UnusedImport
except ImportError:
    pass


DEFAULT_SERVER = 'licensing.zubax.com'
APP_DATA_PATH = os.path.join(os.path.expanduser("~"), '.zubax', 'drwatson')
REQUEST_TIMEOUT = 20


colorama.init()

# Default config - can be overriden later
logging.basicConfig(stream=sys.stderr, level=logging.WARN, format='%(asctime)s %(levelname)s %(name)s: %(message)s')

logger = logging.getLogger(__name__)

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

            provided_login = input(('Login [%s]: ' % login) if login else 'Login: ')
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
            logging.info('Downloaded %d bytes from %r', len(data), url)
            return decode(data)
        raise DrwatsonException('Could not download %r: %r' % (url, r))
    else:
        with open(url, 'rb') as f:
            return decode(f.read())


def _print_impl(color, fmt, *args, end='\n'):
    sys.stdout.write(colorama.Style.BRIGHT)  # @UndefinedVariable
    sys.stdout.write(color)
    sys.stdout.write(fmt % args)
    if end:
        sys.stdout.write(end)
    sys.stdout.write(colorama.Style.RESET_ALL)  # @UndefinedVariable
    sys.stdout.flush()

imperative = partial(_print_impl, colorama.Fore.GREEN)  # @UndefinedVariable
error = partial(_print_impl, colorama.Fore.RED)         # @UndefinedVariable
info = partial(_print_impl, colorama.Fore.WHITE)        # @UndefinedVariable


_native_input = input


def input(fmt, *args, yes_no=False):            # @ReservedAssignment
    with CLIWaitCursorSuppressor():
        text = fmt % args
        if yes_no:
            text = text.rstrip() + ' (y/N) '

        sys.stdout.write(colorama.Style.BRIGHT)     # @UndefinedVariable
        sys.stdout.write(colorama.Fore.GREEN)       # @UndefinedVariable

        out = _native_input(text)
        sys.stdout.write(colorama.Style.RESET_ALL)  # @UndefinedVariable
        sys.stdout.flush()

        if yes_no:
            out = (out[0].lower() == 'y') if out else False
            info('Answered %s', 'YES' if out else 'NO')
            return out
        else:
            return out


def fatal(fmt, *args):
    error(fmt, *args)
    exit(1)


class AbortException(DrwatsonException):
    pass


def abort(reason):
    raise AbortException(str(reason))


def run(handler):
    while True:
        try:
            print('=' * 80)
            input('Press ENTER to begin')

            handler()

            info('Completed successfully')
        except KeyboardInterrupt:
            info('Exit')
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

    for name, lg in logging.Logger.manager.loggerDict.items():  # @UndefinedVariable
        if name.startswith('urllib'):
            continue
        if lg.level < logging_level:
            lg.setLevel(logging_level)

    if require_root and os.geteuid() != 0:
        fatal('This program requires superuser priveleges')

    info('Color legend:')
    imperative('\tFOLLOW INSTRUCTIONS IN GREEN')
    error('\tERRORS ARE REPORTED IN RED')
    info('\tINFO MESSAGES ARE PRINTED IN WHITE')
    info('Press CTRL+C to exit the application')

    return args


class CLIWaitCursor(threading.Thread):
    """Usage:
    with CLIWaitCursor():
        long_operation()
    """

    SUPPRESSED = 0

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


class CLIWaitCursorSuppressor:
    def __enter__(self):
        CLIWaitCursor.SUPPRESSED += 1

    def __exit__(self, _type, _value, _traceback):
        CLIWaitCursor.SUPPRESSED -= 1
