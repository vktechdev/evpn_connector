# -*-coding: utf-8 -*-
# vim: sw=4 ts=4 expandtab ai
#
#    Copyright 2022 VK Cloud.
#
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import six

if six.PY3:
    import subprocess
else:
    import subprocess32 as subprocess


LOG = logging.getLogger(__name__)


def _check_output(command_string):
    return subprocess.check_output(
        command_string, stderr=subprocess.STDOUT, shell=True
    )


class ShellCommandResult(object):
    def __init__(self, command, popen):
        super(ShellCommandResult, self).__init__()
        self.command = command
        self._popen = popen
        self._stdout_data = None
        self._stderr_data = None

    @property
    def ok(self):
        return not bool(self.exit_code)

    @property
    def exit_code(self):
        self._communicate()
        return self._popen.wait()

    def _communicate(self):
        if self._popen.returncode is None:
            self._stdout_data, self._stderr_data = self._popen.communicate()

    @property
    def output(self):
        self._communicate()
        return self._stdout_data

    def __repr__(self):
        return (
            "%(class_name)s(command=%(command)s, exit_code=%(exit_code)s)"
            % {
                "class_name": self.__class__.__name__,
                "command": self.command,
                "exit_code": self._popen.returncode,
            }
        )


def runsh(command, enable_sudo=False, shell=False):
    if enable_sudo:
        command.insert(0, "sudo")
    if shell:
        result = ShellCommandResult(
            command=command,
            popen=subprocess.Popen(
                args=" ".join(command),
                stdout=subprocess.PIPE,
                shell=shell,
                env={},
            ),
        )
    else:
        result = ShellCommandResult(
            command=command,
            popen=subprocess.Popen(
                args=command, stdout=subprocess.PIPE, shell=shell, env={}
            ),
        )
    LOG.info(
        "Execute [ %s ] with exit_code=%s", " ".join(command), result.exit_code
    )
    return result
