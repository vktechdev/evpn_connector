#  coding=utf-8
#
#  Copyright 2025 VK Cloud.
#
#  All Rights Reserved.
#
#     Licensed under the Apache License, Version 2.0 (the "License"); you may
#     not use this file except in compliance with the License. You may obtain
#     a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#     WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#     License for the specific language governing permissions and limitations
#     under the License.

import logging
import sys

from oslo_config import cfg

from evpn_connector.common import constants
from evpn_connector import version

try:
    import sentry_sdk
except ImportError:
    sentry_sdk = None


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

SERVICE_UNDEFINED = "undefined"
SENTRY_TAG_SERVICE = "service"


if sentry_sdk:

    def setup_sentry(service=None):
        if CONF[constants.CONF_GROUP_SENTRY].enabled:
            sentry_sdk.init(
                dsn=CONF[constants.CONF_GROUP_SENTRY].dsn,
                traces_sample_rate=CONF[
                    constants.CONF_GROUP_SENTRY
                ].traces_sample_rate,
                environment=CONF[constants.CONF_GROUP_SENTRY].env,
                attach_stacktrace=True,
                release=version.version_info.release_string(),
            )
            service = service or SERVICE_UNDEFINED
            sentry_sdk.set_tag(SENTRY_TAG_SERVICE, service)

    def capture_exception(error=None, scope=None, **scope_args):
        return sentry_sdk.capture_exception(
            error=error, scope=scope, **scope_args
        )

else:

    def setup_sentry(service=None):
        if CONF[constants.CONF_GROUP_SENTRY].enabled:
            LOG.error("The sentry_sdk library is not installed!")
            sys.exit(5)

    def capture_exception(error=None, scope=None, **scope_args):
        pass
