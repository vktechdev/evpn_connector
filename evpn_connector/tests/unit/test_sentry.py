# Copyright 2025 VK Cloud.
#
# All Rights Reserved.
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


import mock
from oslo_config import cfg

from evpn_connector.common import conf_opts
from evpn_connector.common import sentry

CONF = cfg.CONF


class TestSentry(object):
    def setup_method(self):
        conf_opts.register_sentry_opts()
        CONF.set_override("enabled", True, group="sentry")
        CONF.set_override("dsn", "http://123@test/1", group="sentry")
        CONF.set_override("traces_sample_rate", 0.5, group="sentry")
        CONF.set_override("env", "test", group="sentry")

    def teardown_method(self):
        CONF._unset_defaults_and_overrides()

    @mock.patch("evpn_connector.common.sentry.sentry_sdk")
    def test_setup_sentry_success(self, mock_sentry_sdk):
        mock_sentry_sdk.init = mock.MagicMock()
        mock_sentry_sdk.set_tag = mock.MagicMock()

        sentry.setup_sentry(service="evpn_connector")

        mock_sentry_sdk.init.assert_called_once()
        mock_sentry_sdk.set_tag.assert_called_once_with(
            "service", "evpn_connector"
        )

    @mock.patch("evpn_connector.common.sentry.sentry_sdk")
    @mock.patch("evpn_connector.version.version_info.release_string")
    def test_setup_sentry_enabled(self, mock_release, mock_sentry_sdk):
        mock_release.return_value = "1"
        mock_sentry_sdk.init = mock.MagicMock()

        sentry.setup_sentry(service="evpn_connector")

        mock_sentry_sdk.init.assert_called_once_with(
            dsn="http://123@test/1",
            traces_sample_rate=0.5,
            environment="test",
            attach_stacktrace=True,
            release="1",
        )

    @mock.patch("evpn_connector.common.sentry.sentry_sdk")
    def test_setup_sentry_disabled(self, mock_sentry_sdk):
        CONF.set_override("enabled", False, group="sentry")

        sentry.setup_sentry(service="evpn_connector")

        mock_sentry_sdk.init.assert_not_called()
        mock_sentry_sdk.set_tag.assert_not_called()

    @mock.patch("evpn_connector.common.sentry.sentry_sdk")
    def test_capture_exception(self, mock_sentry_sdk):
        mock_sentry_sdk.init = mock.MagicMock()
        mock_sentry_sdk.capture_exception = mock.MagicMock()
        test_error = Exception("Test error")

        sentry.capture_exception(error=test_error)

        mock_sentry_sdk.capture_exception.assert_called_once_with(
            error=test_error, scope=None
        )
