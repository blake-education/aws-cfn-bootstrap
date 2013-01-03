#!/usr/bin/env python

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

from distutils.core import setup, Distribution
import sys

name = 'aws-cfn-bootstrap'
version = '1.3'

if sys.version_info[0] == 2 and sys.version_info[1] < 6:
        print >> sys.stderr, "Python 2.6+ is required"
        sys.exit(1)

rpm_requires = ['python >= 2.6', 'python-daemon', 'python-requests']
dependencies = ['python-daemon>=1.5.2', 'requests>=0.11.1,<1.0.0']

_distclass = Distribution
_opts = {
         'build_scripts': { 'executable': '/usr/bin/env python' },
         'bdist_rpm' : { 'requires' : rpm_requires }
        }
_data_files = [('share/doc/%s-%s' % (name, version), ['license/NOTICE.txt', 'license/LICENSE.txt']),
                ('init/redhat', ['init/cfn-hup'])]
try:
    import py2exe
    import certifi
    class WindowsDistribution(Distribution):
        def __init__(self, attrs):
            self.com_server = []
            self.ctypes_com_server = []
            self.service = ["cfnbootstrap.winhup"]
            self.isapi = []
            self.windows = []
            self.zipfile = 'library.zip'
            self.console = ['bin/cfn-init', 'bin/cfn-signal', 'bin/cfn-get-metadata', 'bin/cfn-hup', 'bin/cfn-elect-cmd-leader', 'bin/cfn-send-cmd-result']
            Distribution.__init__(self, attrs)
    _distclass = WindowsDistribution
    _opts['py2exe'] = {
                        'typelibs' : [('{000C1092-0000-0000-C000-000000000046}', 1033, 1, 0),
                                      ('{E34CB9F1-C7F7-424C-BE29-027DCC09363A}', 0, 1, 0)],
                        'excludes' : ['certifi', 'pyreadline', 'difflib', 'distutils', 'doctest', 'pdb', 'inspect', 'unittest', 'adodbapi'],
                        'includes' : ['chardet', 'dbhash'],
                        'dll_excludes' : ['msvcr71.dll', 'w9xpopen.exe', ''],
                        'compressed' : True,
                      }
    _data_files = [('', ['license/win/NOTICE.txt', 'license/win/LICENSE.rtf', certifi.where()])]
except ImportError:
    pass


setup(
    distclass = _distclass,
    name=name,
    version=version,
    description='An EC2 bootstrapper for CloudFormation',
    long_description="Bootstraps EC2 instances by retrieving and processing the Metadata block of a CloudFormation resource.",
    author='AWS CloudFormation',
    url='http://aws.amazon.com/cloudformation/',
    license='Apache 2.0',
    classifiers = ['License :: OSI Approved :: Apache Software License'],
    packages=['cfnbootstrap'],
    install_requires=dependencies,
    scripts=['bin/cfn-init', 'bin/cfn-signal', 'bin/cfn-get-metadata', 'bin/cfn-hup', 'bin/cfn-elect-cmd-leader', 'bin/cfn-send-cmd-result'],
    data_files=_data_files,
    options=_opts
)
