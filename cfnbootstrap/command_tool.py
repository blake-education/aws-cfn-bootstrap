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
from cfnbootstrap.construction_errors import ToolError
from cfnbootstrap.util import ProcessHelper, interpret_boolean
import logging
import os.path
import subprocess
try:
    import simplejson as json
except ImportError:
    import json

log = logging.getLogger("cfn.init")

class CommandTool(object):
    """
    Executes arbitrary commands
    """

    def apply(self, action):
        """
        Execute a set of commands, returning a list of commands that were executed.

        Arguments:
        action -- a dict of command to attributes, where attributes has keys of:
            command: the command to run (a string or list)
            cwd: working directory (a string)
            env: a dictionary of environment variables
            test: a commmand to run; if it returns zero, the command will run
            ignoreErrors: if true, ignore errors
            waitAfterCompletion: # of seconds to wait after completion (or "forever")
            defaults: a command to run; the stdout will be used to provide defaults

        Exceptions:
        ToolError -- on expected failures
        """

        commands_run = []

        if not action:
            log.debug("No commands specified")
            return commands_run

        for name in sorted(action.keys()):
            log.debug("Running command %s", name)

            attributes = action[name]

            if "defaults" in attributes:
                log.debug("Generating defaults for command %s", name)
                defaultsResult = ProcessHelper(attributes['defaults'], stderr=subprocess.PIPE).call()
                log.debug("Defaults script for %s output: %s", name, defaultsResult.stdout)
                if defaultsResult.returncode:
                    log.error("Defaults script failed for %s: %s", name, defaultsResult.stderr)
                    raise ToolError("Defaults script for command %s failed" % name)

                old_attrs = attributes
                attributes = json.loads(defaultsResult.stdout)
                attributes.update(old_attrs)

            if not "command" in attributes:
                log.error("No command specified for %s", name)
                raise ToolError("%s does not specify the 'command' attribute, which is required" % name)

            cwd = os.path.expanduser(attributes["cwd"]) if "cwd" in attributes else None
            env = attributes.get("env", None)

            if "test" in attributes:
                log.debug("Running test for command %s", name)
                test = attributes["test"]
                testResult = ProcessHelper(test, env=env, cwd=cwd).call()
                log.debug("Test command output: %s", testResult.stdout)
                if testResult.returncode:
                    log.info("Test failed with code %s", testResult.returncode)
                    continue
                else:
                    log.debug("Test for command %s passed", name)
            else:
                log.debug("No test for command %s", name)

            cmd_to_run = attributes["command"]
            if "runas" in attributes:
                if os.name == 'nt':
                    raise ToolError('Command %s specified "runas", which is not supported on Windows' % name)

                if isinstance(cmd_to_run, basestring):
                    cmd_to_run = 'su %s -c %s' % (attributes['runas'], cmd_to_run)
                else:
                    cmd_to_run = ['su', attributes['runas'], '-c'] + cmd_to_run

            commandResult = ProcessHelper(cmd_to_run, env=env, cwd=cwd).call()

            if commandResult.returncode:
                log.error("Command %s (%s) failed", name, attributes["command"])
                log.debug("Command %s output: %s", name, commandResult.stdout)
                if interpret_boolean(attributes.get("ignoreErrors")):
                    log.info("ignoreErrors set to true, continuing build")
                    commands_run.append(name)
                else:
                    raise ToolError("Command %s failed" % name)
            else:
                log.info("Command %s succeeded", name)
                log.debug("Command %s output: %s", name, commandResult.stdout)
                commands_run.append(name)

        return commands_run

    @classmethod
    def get_wait(cls, cmd_options):
        wait = cmd_options.get('waitAfterCompletion', 60 if os.name == 'nt' else 0)
        if isinstance(wait, basestring) and 'forever' == wait.lower():
            return -1
        return int(wait)
