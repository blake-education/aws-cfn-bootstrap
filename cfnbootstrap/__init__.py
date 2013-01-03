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
import logging.config
import os.path
import sys
import StringIO

_config ="""[loggers]
keys=root,cfninit,cfnclient,cfnhup
[handlers]
keys=%(conf_handler)s
[formatters]
keys=amzn
[logger_root]
level=NOTSET
handlers=%(conf_handler)s
[logger_cfninit]
level=NOTSET
handlers=%(conf_handler)s
qualname=cfn.init
propagate=0
[logger_cfnhup]
level=NOTSET
handlers=%(conf_handler)s
qualname=cfn.hup
propagate=0
[logger_cfnclient]
level=NOTSET
handlers=%(conf_handler)s
qualname=cfn.client
propagate=0
[handler_default]
class=handlers.RotatingFileHandler
level=%(conf_level)s
formatter=amzn
args=('%(conf_file)s', 'a', 5242880, 5)
[handler_tostderr]
class=StreamHandler
level=%(conf_level)s
formatter=amzn
args=(sys.stderr,)
[formatter_amzn]
format=%(asctime)s [%(levelname)s] %(message)s
datefmt=
class=logging.Formatter
"""

def _getLogFile(filename):
    if os.name == 'nt':
        logdir = os.path.expandvars(r'${SystemDrive}\cfn\log')
        if not os.path.exists(logdir):
            os.makedirs(logdir)
        return logdir + os.path.sep + filename

    return '/var/log/%s' % filename


def configureLogging(level='INFO', quiet=False, filename='cfn-init.log', log_dir=None):
    if not log_dir:
        output_file=_getLogFile(filename)
    else:
        output_file = os.path.join(log_dir, filename)

    try:
        logging.config.fileConfig(StringIO.StringIO(_config), {'conf_level' : level, 'conf_handler' : 'default', 'conf_file' : output_file})
    except IOError:
        if not quiet:
            print >> sys.stderr, "Could not open %s for logging.  Using stderr instead." % output_file
        logging.config.fileConfig(StringIO.StringIO(_config), {'conf_level' : level, 'conf_handler' : 'tostderr'})

configureLogging(quiet=True)