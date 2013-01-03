#==============================================================================
# Copyright 2011 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#==============================================================================
from requests.exceptions import ConnectionError, HTTPError, Timeout, \
    RequestException, SSLError
import StringIO
import imp
import logging
import os.path
import random
import re
import requests
import stat
import subprocess
import sys
import time
try:
    import simplejson as json
except ImportError:
    import json

log = logging.getLogger("cfn.init")

def main_is_frozen():
    return (hasattr(sys, "frozen") or # new py2exe
            hasattr(sys, "importers") # old py2exe
            or imp.is_frozen("__main__")) # tools/freeze

def get_cert():
    if main_is_frozen():
        return os.path.join(os.path.dirname(sys.executable), 'cacert.pem')
    return True # True tells Requests to find its own cert

def get_instance_identity_document():
    return requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').text.rstrip()

def get_instance_identity_signature():
    return requests.get('http://169.254.169.254/latest/dynamic/instance-identity/signature').text.rstrip()

_instance_id = '__unset'

def get_instance_id():
    """
    Attempt to retrieve an EC2 instance id, returning None if this is not EC2
    """
    global _instance_id
    if _instance_id == '__unset':
        try:
            _instance_id = requests.get('http://169.254.169.254/latest/meta-data/instance-id', timeout=2, config={'danger_mode' : True}).text.strip()
        except RequestException:
            log.exception("Exception retrieving InstanceId")
            _instance_id =  None

    return _instance_id

def is_ec2():
    return get_instance_id() != None

_trues = frozenset([True, 1, 'true', 'yes', 'y', '1'])

def interpret_boolean(input):
    """
    This tries to interpret if the user intended True
    I don't use python's boolean equivalent because it's
    likely that we're getting a string
    """
    if not input:
        return False

    input = input.lower().strip() if isinstance(input, basestring) else input

    return input in _trues

def extract_credentials(path):
    """
    Extract credentials from a file at path, returning tuple of (access_key, secret_key)
    Raises an exception if the file is readable by group or other.
    """
    if not os.path.isfile(path):
        raise IOError(None, "Credential file was not found at %s" % path)

    if os.name == 'posix':
        mode = os.stat(path)[stat.ST_MODE]

        if stat.S_IRWXG & mode or stat.S_IRWXO & mode:
            raise IOError(None, "Credential file cannot be accessible by group or other. Please chmod 600 the credential file.")

    access_key, secret_key = '', ''
    with file(path, 'r') as f:
        for line in (line.strip() for line in f):
            if line.startswith("AWSAccessKeyId="):
                access_key = line.partition('=')[2]
            elif line.startswith("AWSSecretKey="):
                secret_key = line.partition('=')[2]

    if not access_key or not secret_key:
        raise IOError(None, "Credential file must contain the keys 'AWSAccessKeyId' and 'AWSSecretKey'")

    return (access_key, secret_key)

_dot_split = re.compile(r'(?<!\\)\.')
_slash_replace = re.compile(r'\\(?=\.)')

def extract_value(metadata, path):
    """Returns a value from metadata (a dict) at a (possibly empty) path, where path is in dotted object syntax (like root.child.leaf)"""
    if not path:
        return metadata

    return_data = metadata
    for element in (_slash_replace.sub('', s) for s in _dot_split.split(path)):
        if not element in return_data:
            log.debug("No value at path %s (missing index: %s)", path, element)
            return None
        return_data = return_data[element]

    return return_data

def exponential_backoff(max_tries):
    """
    Returns a series of floating point numbers between 0 and 2^i-1 for i in 0 to max_tries
    """
    return [random.random() * (2**i - 1) for i in range(0, max_tries)]

def extend_backoff(durations):
    """
    Adds another exponential delay time to a list of delay times
    """
    durations.append(random.random() * (2**len(durations) - 1))

def _extract_http_error(resp):
    if resp.status_code == 503:
        retry_mode='RETRIABLE_FOREVER'
    elif resp.status_code < 500 and resp.status_code not in (404, 408):
        retry_mode='TERMINAL'
    else:
        retry_mode='RETRIABLE'

    return RemoteError(resp.status_code, "HTTP Error %s : %s" % (resp.status_code, resp.text), retry_mode)

class RemoteError(IOError):

    retry_modes = frozenset(['TERMINAL', 'RETRIABLE', 'RETRIABLE_FOREVER'])

    def __init__(self, code, msg, retry_mode='RETRIABLE'):
        super(RemoteError, self).__init__(code, msg)
        if not retry_mode in RemoteError.retry_modes:
            raise ValueError("Invalid retry mode: %s" % retry_mode)
        self.retry_mode = retry_mode

def retry_on_failure(max_tries = 5, http_error_extractor=_extract_http_error):
    def _decorate(f):
        def _retry(*args, **kwargs):
            durations = exponential_backoff(max_tries)
            for i in durations:
                if i > 0:
                    log.debug("Sleeping for %f seconds before retrying", min(i, 20))
                    time.sleep(min(i, 20))

                try:
                    return f(*args, **kwargs)
                except SSLError, e:
                    log.exception("SSLError")
                    raise RemoteError(None, str(e), retry_mode='TERMINAL')
                except ConnectionError, e:
                    log.exception('ConnectionError')
                    last_error = RemoteError(None, str(e))
                except HTTPError, e:
                    last_error = http_error_extractor(e.response)
                    if last_error.retry_mode == 'TERMINAL':
                        raise last_error
                    elif last_error.retry_mode == 'RETRIABLE_FOREVER':
                        extend_backoff(durations)

                    log.exception(last_error.strerror)
                except Timeout, e:
                    log.exception('Timeout')
                    last_error = RemoteError(None, str(e))
            else:
                raise last_error
        return _retry
    return _decorate

def json_from_response(resp):
    if hasattr(resp, 'json'):
        return resp.json
    return json.load(StringIO.StringIO(resp.content))

class ProcessResult(object):
    """
    Return object for ProcessHelper

    """

    def __init__(self, returncode, stdout, stderr):
        self._returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    @property
    def returncode(self):
        return self._returncode

    @property
    def stdout(self):
        return self._stdout

    @property
    def stderr(self):
        return self._stderr

class ProcessHelper(object):
    """
    Helper to simplify command line execution

    """

    def __init__(self, cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=None, cwd=None):
        self._cmd = cmd
        self._stdout = stdout
        self._stderr = stderr
        if not env:
            self._env = None
        elif os.name == 'nt': # stringify the environment in Windows, which cannot handle unicodes
            self._env = dict(((str(k), str(v)) for k,v in env.iteritems()))
        else:
            self._env = dict(env)
        self._cwd = cwd

    def call(self):
        """
        Calls the command, returning a tuple of (returncode, stdout, stderr)
        """

        process = subprocess.Popen(self._cmd, stdout=self._stdout, stderr=self._stderr,
                                   shell=isinstance(self._cmd, basestring), env=self._env, cwd=self._cwd)
        returnData = process.communicate()

        return ProcessResult(process.returncode, returnData[0], returnData[1])
