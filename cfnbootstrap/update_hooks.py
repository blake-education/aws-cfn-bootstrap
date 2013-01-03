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
from cfnbootstrap import util
from cfnbootstrap.aws_client import Credentials
from cfnbootstrap.cfn_client import CloudFormationClient
from cfnbootstrap.sqs_client import SQSClient
from cfnbootstrap.util import ProcessHelper
from threading import Timer
import ConfigParser
import calendar
import collections
import contextlib
import datetime
import logging
import os
import random
import shelve
import socket
import subprocess
import tempfile
import time
try:
    import simplejson as json
except ImportError:
    import json

log = logging.getLogger("cfn.hup")

def parse_config(config_path):
    main_conf_path = os.path.join(config_path, 'cfn-hup.conf')
    if not os.path.isfile(main_conf_path):
        raise ValueError("Could not find main configuration at %s" % main_conf_path)

    main_config = ConfigParser.SafeConfigParser()
    main_config.read(main_conf_path)

    if not main_config.has_option('main', 'stack'):
        raise ValueError("[main] section must contain stack option")

    stack = main_config.get('main', 'stack')

    if main_config.has_option('main', 'credential-file'):
        try:
            access_key, secret_key = util.extract_credentials(main_config.get('main', 'credential-file'))
        except IOError, e:
            raise ValueError("Could not retrieve credentials from file:\n\t%s" % e.strerror)
    else:
        access_key, secret_key = ('', '')

    additional_hooks_path = os.path.join(config_path, 'hooks.d')
    additional_files = []
    if os.path.isdir(additional_hooks_path):
        for hook_file in os.listdir(additional_hooks_path):
            if os.path.isfile(os.path.join(additional_hooks_path, hook_file)):
                additional_files.append(os.path.join(additional_hooks_path, hook_file))

    hooks_config = ConfigParser.SafeConfigParser()
    files_read = hooks_config.read([os.path.join(config_path, 'hooks.conf')] + additional_files)

    if not files_read:
        raise ValueError("No hook configurations found at %s or %s.", os.path.join(config_path, 'hooks.conf'), additional_hooks_path)

    hooks = []
    cmd_hooks = []

    for section in hooks_config.sections():
        if not hooks_config.has_option(section, 'triggers'):
            logging.error("No triggers specified for hook %s", section)
            continue

        triggers = [s.strip() for s in hooks_config.get(section, 'triggers').split(',')]

        if not hooks_config.has_option(section, 'path'):
            logging.error("No path specified for hook %s", section)
            continue

        if not hooks_config.has_option(section, 'action'):
            logging.error("No action specified for hook %s", section)
            continue

        runas = None
        if hooks_config.has_option(section, 'runas'):
            runas = hooks_config.get(section, 'runas').strip()

        hook = Hook(section,
                    triggers,
                    hooks_config.get(section, 'path').strip(),
                    hooks_config.get(section, 'action'),
                    runas)
        if hook.is_cmd_hook():
            if hooks_config.has_option(section, 'singleton'):
                hook.singleton = util.interpret_boolean(hooks_config.get(section, 'singleton'))
            if hooks_config.has_option(section, 'send_result'):
                hook.send_result = util.interpret_boolean(hooks_config.get(section, 'send_result'))
            cmd_hooks.append(hook)
        else:
            hooks.append(hook)

    if not hooks and not cmd_hooks:
        raise ValueError("No valid hooks found")

    region = 'us-east-1'
    if main_config.has_option('main', 'region'):
        region = main_config.get('main', 'region')

    cfn_url = CloudFormationClient.endpointForRegion(region)

    if main_config.has_option('main', 'url'):
        cfn_url = main_config.get('main', 'url')

    cfn_client = CloudFormationClient(Credentials(access_key, secret_key), cfn_url, region)

    if hooks:
        processor = HookProcessor(hooks, stack, cfn_client)
    else:
        processor = None

    if cmd_hooks:
        sqs_url = SQSClient.endpointForRegion(region)
        if main_config.has_option('main', 'sqs_url'):
            sqs_url = main_config.get('main', 'sqs_url')

        sqs_client = SQSClient(Credentials(access_key, secret_key), sqs_url)

        cmd_processor = CmdProcessor(stack, cmd_hooks, sqs_client,
                                     CloudFormationClient(Credentials(access_key, secret_key), cfn_url, region))
    else:
        cmd_processor = None

    return (main_config, processor, cmd_processor)

class FatalUpdateError(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class InFlightStatusError(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class Hook(object):

    def __init__(self, name, triggers, path, action, runas):
        self._triggers = triggers[:]
        self._path = path
        self._action = action
        self._name = name
        self._runas = runas
        self.singleton = False
        self.send_result = True

    @property
    def triggers(self):
        return self._triggers

    @property
    def path(self):
        return self._path

    @property
    def action(self):
        return self._action

    @property
    def name(self):
        return self._name

    @property
    def runas(self):
        return self._runas

    def is_cmd_hook(self):
        return self._triggers == ['on.command']

class AutoRefreshingCredentialsProvider(object):

    def __init__(self, cfn_client, stack_name, listener_id):
        self._cfn_client = cfn_client
        self._stack_name = stack_name
        self._listener_id = listener_id
        self._creds = None
        self._last_timer = None
        self.listener_expired = False

    def refresh(self):
        log.info("Refreshing listener credentials")
        if self._last_timer:
            self._last_timer.cancel()

        try:
            self._creds = self._cfn_client.get_listener_credentials(self._stack_name, self._listener_id)
            self.listener_expired = False
        except IOError, e:
            if hasattr(e, 'error_code') and 'ListenerExpired' == e.error_code:
                self.listener_expired = True
                log.exception("Listener expired")
            else:
                self.listener_expired = False
                log.exception("IOError caught while refreshing credentials")
        except Exception:
            self.listener_expired = False
            log.exception("Exception refreshing credentials")

        now = time.time()
        expiration = calendar.timegm(self._creds.expiration.utctimetuple()) if self._creds else now
        remaining = expiration - now

        if remaining > 30 * 60:
            next_refresh = min(2 * 60 * 60, remaining / 2)
        else:
            next_refresh = 60 * random.random()

        log.info("Scheduling next credential refresh in %s seconds", next_refresh)
        t = Timer(next_refresh, self.refresh)
        t.daemon = True
        t.start()
        self._last_timer = t

    def creds_expired(self):
        return self._creds and self._creds.expiration < datetime.datetime.utcnow()

    @property
    def credentials(self):
        for i in range(3):
            if self._creds:
                break
            self.refresh()

        if not self._creds:
            raise ValueError('Could not retrieve listener credentials')

        return self._creds

class CmdProcessor(object):
    """Processes CommandService hooks"""

    def __init__(self, stack_name, hooks, sqs_client, cfn_client):
        """Takes a list of Hook objects and processes them"""
        self.stack_name = stack_name
        self.hooks = self._hooks_by_path(hooks)
        self.sqs_client = sqs_client
        self.cfn_client = cfn_client
        self.listener_id = util.get_instance_id() if util.is_ec2() else socket.getfqdn()
        self._create_shelf_dir()
        self._creds_provider = AutoRefreshingCredentialsProvider(self.cfn_client, self.stack_name, self.listener_id)
        self.queue_url = None

    def is_registered(self):
        return self.queue_url is not None and not self._creds_provider.listener_expired

    def creds_expired(self):
        return self._creds_provider.creds_expired()

    def register(self):
        self.queue_url = self.cfn_client.register_listener(self.stack_name, self.listener_id).queue_url
        self._creds_provider.listener_expired = False

    def _create_shelf_dir(self):
        if os.name == 'nt':
            self.shelf_dir = os.path.expandvars(r'${SystemDrive}\cfn\cfn-hup\data')
        else:
            self.shelf_dir = '/var/lib/cfn-hup/data'
        if not os.path.isdir(self.shelf_dir):
            log.debug("Creating %s", self.shelf_dir)
            try:
                os.makedirs(self.shelf_dir)
            except OSError:
                log.warn("Could not create %s; using temporary directory", self.shelf_dir)
                self.shelf_dir = tempfile.mkdtemp()

    def process(self):
        if self.queue_url is None:
            raise FatalUpdateError("Cannot process command hooks before registering")

        with contextlib.closing(shelve.open(os.path.join(self.shelf_dir, 'command_db'))) as shelf:
            try:
                for msg in self.sqs_client.receive_message(self.queue_url, request_credentials = self._creds_provider.credentials):
                    if self._process_msg(msg, shelf):
                        self.sqs_client.delete_message(self.queue_url, msg.receipt_handle, request_credentials = self._creds_provider.credentials)
            except FatalUpdateError:
                raise
            except IOError, e:
                if hasattr(e, 'error_code') and 'AWS.SimpleQueueService.NonExistentQueue' == e.error_code:
                    self.queue_url = None
                log.exception("IOError caught while processing messages")
            except Exception:
                log.exception("Exception caught while processing messages")

    def _process_msg(self, msg, shelf):
        log.debug("Processing message: %s", msg)

        try:
            cmd_msg = json.loads(json.loads(msg.body)['Message'])
            log.debug("Command message: %s", cmd_msg)

            expiration = datetime.datetime.utcfromtimestamp(int(cmd_msg['Expiration']) / 1000)
            cmds_run = shelf.get('commands_run', collections.defaultdict(set))
            cmd_invocation = '%s|%s' % (cmd_msg['CommandName'], cmd_msg['InvocationId'])

            if expiration < datetime.datetime.utcnow():
                log.info("Invocation %s of command %s for stack %s expired at %s; skipping",
                            cmd_msg['InvocationId'], cmd_msg['CommandName'], cmd_msg['DispatcherId'],
                            expiration.isoformat())
            elif cmd_invocation in cmds_run[cmd_msg['DispatcherId']]:
                log.info("Invocation %s of command %s for stack %s has already run; skipping",
                            cmd_msg['InvocationId'], cmd_msg['CommandName'], cmd_msg['DispatcherId'])
            else:
                log.info("Received command %s (invocation id: %s)", cmd_msg['CommandName'], cmd_msg['InvocationId'])
                hook_to_run = self.hooks.get(cmd_msg['CommandName'])
                if not hook_to_run or self._run_hook(hook_to_run, cmd_msg):
                    cmds_run[cmd_msg['DispatcherId']].add(cmd_invocation)
                    shelf['commands_run'] = cmds_run
                else:
                    return False # transient failure, leave in queue
        except (ValueError, KeyError):
            log.exception("Invalid message received; deleting it")

        return True

    def _run_hook(self, hook, cmd_msg):
        if hook.singleton:
            log.info("Hook %s is configured to run as a singleton", hook.name)
            leader = self.cfn_client.elect_command_leader(self.stack_name,
                                                          cmd_msg['CommandName'],
                                                          cmd_msg['InvocationId'],
                                                          self.listener_id)
            if leader == self.listener_id:
                log.info("This listener is the leader.  Continuing with action")
            else:
                log.info("This listener is not the leader; %s is the leader.", leader)
                return True

        action_env = self._get_environment(cmd_msg)
        result_queue = cmd_msg['ResultQueue']

        log.info("Running action for %s", hook.name)
        log.debug("Action environment: %s", action_env)

        action = hook.action
        if hook.runas:
            action = ['su', hook.runas, '-c', action]

        result = ProcessHelper(action, stderr=subprocess.PIPE, env=action_env).call()

        log.debug("Action for %s output: %s", hook.name, result.stdout if result.stdout else '<None>')

        if not hook.send_result:
            return True

        result_msg = { 'DispatcherId' : cmd_msg['DispatcherId'],
                       'InvocationId' : cmd_msg['InvocationId'],
                       'CommandName' : cmd_msg['CommandName'],
                       'Status' : "FAILURE" if result.returncode else "SUCCESS",
                       'ListenerId' : self.listener_id }

        if result.returncode:
            result_stderr = result.stderr.rstrip()
            log.warn("Action for %s exited with %s, returning FAILURE", hook.name, result.returncode)
            result_msg['Message'] = result_stderr if len(result_stderr) <= 1024 else result_stderr[0:500] + '...' + result_stderr[-500:]
        else:
            result_stdout = result.stdout.rstrip()
            if len(result_stdout) > 1024:
                log.error("stdout for %s was greater than 1024 in length, which is not allowed", hook.name)
                result_msg['Status'] = 'FAILURE'
                result_msg['Message'] = 'Result data was longer than 1024 bytes. Started with: ' + result_stdout[0:100]
            else:
                log.info("Action for %s succeeded, returning SUCCESS", hook.name)
                result_msg['Data'] = result_stdout

        try:
            self.sqs_client.send_message(result_queue, json.dumps(result_msg), request_credentials=self._creds_provider.credentials)
        except Exception:
            log.exception('Error sending result; will leave message in queue')
            return False

        return True

    def _hooks_by_path(self, hooks):
        ret_hooks = {}
        for hook in hooks:
            if hook.path in ret_hooks:
                raise FatalUpdateError("Multiple hooks for the same command (%s)" % hook.path)
            ret_hooks[hook.path] = hook
        return ret_hooks

    def _get_environment(self, cmd_msg):
        action_env = dict(os.environ)
        action_env['CMD_DATA'] = cmd_msg['Data']
        action_env['INVOCATION_ID'] = cmd_msg['InvocationId']
        action_env['DISPATCHER_ID'] = cmd_msg['DispatcherId']
        action_env['CMD_NAME'] = cmd_msg['CommandName']
        action_env['STACK_NAME'] = self.stack_name
        action_env['LISTENER_ID'] = self.listener_id
        action_env['RESULT_QUEUE'] = cmd_msg['ResultQueue']
        creds = self._creds_provider.credentials
        action_env['RESULT_ACCESS_KEY'] = creds.access_key
        action_env['RESULT_SECRET_KEY'] = creds.secret_key
        action_env['RESULT_SESSION_TOKEN'] = creds.security_token
        return action_env


class HookProcessor(object):
    """Processes update hooks"""

    def __init__(self, hooks, stack_name, client):
        """Takes a list of Hook objects and processes them"""
        self.hooks = hooks
        if os.name == 'nt':
            self.dir = os.path.expandvars(r'${SystemDrive}\cfn\cfn-hup\data')
        else:
            self.dir = '/var/lib/cfn-hup/data'
        if not os.path.isdir(self.dir):
            log.debug("Creating %s", self.dir)
            try:
                os.makedirs(self.dir)
            except OSError:
                log.warn("Could not create %s; using temporary directory", self.dir)
                self.dir = tempfile.mkdtemp()

        self.client = client
        self.stack_name = stack_name

    def process(self):
        with contextlib.closing(shelve.open('%s/metadata_db' % self.dir)) as shelf:
            self._resource_cache = {}
            for hook in self.hooks:
                try:
                    self._process_hook(hook, shelf)
                except FatalUpdateError:
                    raise
                except Exception:
                    log.exception("Exception caught while running hook %s", hook.name)

    def _process_hook(self, hook, shelf):
        try:
            new_data = self._retrieve_path_data(hook.path)
        except InFlightStatusError:
            return

        old_data = shelf.get(hook.name + "|" + hook.path, None)

        if 'post.add' in hook.triggers and not old_data and new_data:
            log.info("Previous state not found; action for %s will be run", hook.name)
        elif 'post.remove' in hook.triggers and old_data and not new_data:
            log.info('Path %s was removed; action for %s will be run', hook.path, hook.name)
        elif 'post.update' in hook.triggers and old_data and new_data and old_data != new_data:
            log.info("Data has changed from previous state; action for %s will be run", hook.name)
        else:
            log.debug("No change in path %s for hook %s", hook.path, hook.name)
            shelf[hook.name + '|' + hook.path] = new_data
            return

        log.info("Running action for %s", hook.name)
        action_env = dict(os.environ)
        env_key = self._retrieve_env_key(hook.path)
        if old_data:
            action_env['CFN_OLD_%s' % env_key] = self._as_string(old_data)
        if new_data:
            action_env['CFN_NEW_%s' % env_key] = self._as_string(new_data)

        action = hook.action
        if hook.runas:
            action = ['su', hook.runas, '-c', action]

        result = ProcessHelper(action, env=action_env).call()

        if result.returncode:
            log.warn("Action for %s exited with %s; will retry on next iteration", hook.name, result.returncode)
        else:
            shelf[hook.name + '|' + hook.path] = new_data
        log.debug("Action for %s output: %s", hook.name, result.stdout if result.stdout else '<None>')

    def _as_string(self, obj):
        if isinstance(obj, basestring):
            return obj
        elif isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return json.dumps(obj)

    def _retrieve_env_key(self, path):
        """Given a hook path, return the key to append to environment variables for old/new data"""
        parts = path.split('.', 3)

        if len(parts) < 3:
            return 'LAST_UPDATED'
        elif parts[2].lower() == 'metadata':
            return 'METADATA'
        elif parts[2].lower() == 'physicalresourceid':
            return 'PHYSICAL_RESOURCE_ID'

    def _retrieve_path_data(self, path):
        parts = path.split('.', 3)
        if len(parts) < 2:
            raise FatalUpdateError("Unsupported path: paths must be in the form Resources.<LogicalResourceId>(.Metadata|PhysicalResourceId)(.<optional Metadata subkey>). Input: %s" % path)

        if parts[0].lower() != 'resources':
            raise FatalUpdateError('Unsupported path: only changes to Resources are supported (path: %s)' % path)

        if len(parts) == 2:
            resourcePart = None
        elif parts[2].lower() not in ['metadata', 'physicalresourceid']:
            raise FatalUpdateError("Unsupported path: only Metadata or PhysicalResourceId can be specified after LogicalResourceId (path: %s)" % path)
        else:
            resourcePart = parts[2].lower()

        logical_id = parts[1]
        subpath = ('' if len(parts) < 4 else parts[3])

        if logical_id not in self._resource_cache:
            self._resource_cache[logical_id] = self.client.describe_stack_resource(logical_id, self.stack_name)

        resource = self._resource_cache[logical_id]
        status = resource.resourceStatus

        if status and status.endswith('_IN_PROGRESS'):
            log.debug("Skipping resource %s in %s as it is in status %s", logical_id, self.stack_name, status)
            raise InFlightStatusError('%s in %s is in status %s' % (logical_id, self.stack_name, status))

        if resourcePart == 'metadata':
            if not resource.metadata:
                log.warn("No metadata for %s in %s", logical_id, self.stack_name)
                return None

            return util.extract_value(resource.metadata, subpath)
        elif 'DELETE_COMPLETE' == status:
            return None
        elif resourcePart == 'physicalresourceid':
            return resource.physicalResourceId
        else:
            return resource.lastUpdated
