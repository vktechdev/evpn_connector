# vim: tabstop=4 shiftwidth=4 softtabstop=4
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

from oslo_config import cfg

from evpn_connector.common import constants
from evpn_connector import version


GLOBAL_SERVICE_NAME = constants.GLOBAL_SERVICE_NAME
_CONFIG_NOT_FOUND_MESSAGE = (
    "Unable to find configuration file in the"
    " default search paths (~/.%(service_name)s/, ~/,"
    " /etc/%(service_name)s/, /etc/) and the '--config-file' option!"
    % {"service_name": GLOBAL_SERVICE_NAME}
)


def parse(args):
    cfg.CONF(
        args=args,
        project=GLOBAL_SERVICE_NAME,
        version="%s %s"
        % (
            GLOBAL_SERVICE_NAME.capitalize(),
            version.version_info.release_string(),
        ),
    )
    if not cfg.CONF.config_file:
        logging.warning(_CONFIG_NOT_FOUND_MESSAGE)
    return cfg.CONF.config_file
