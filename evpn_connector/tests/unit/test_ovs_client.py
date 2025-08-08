# Copyright 2024 VK Cloud.
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
import pytest

from evpn_connector.ovs import client
from evpn_connector.service import objects
from evpn_connector.tests.unit import utils


class TestOvSClient(object):
    @pytest.fixture
    def mock_shell_run(self):
        mock_runsh_result = mock.MagicMock(ok=True, exit_code=0, output=b"")
        with mock.patch(
            "evpn_connector.ovs.shell.runsh", return_value=mock_runsh_result
        ) as mock_runsh:
            yield mock_runsh

    def test_create_bridge(self, mock_shell_run):
        ovs_client = client.OvSClient(
            "test_sw", "/tmp/flows.txt", enable_sudo=True
        )

        ovs_client.create_bridge()

        mock_shell_run.assert_called_once_with(
            command=[
                "/usr/bin/ovs-vsctl",
                "--may-exist",
                "add-br",
                "test_sw",
                "--",
                "set",
                "Bridge",
                "test_sw",
                "protocols=OpenFlow13",
                "fail-mode=secure",
            ],
            enable_sudo=True,
        )

    def test_create_tun_port(self, mock_shell_run):
        vxlan_ofport = 10
        local_ip = "1.2.3.4"
        vxlan_udp_port = 3423

        ovs_client = client.OvSClient(
            "test_sw",
            "/tmp/flows.txt",
            vxlan_ofport=vxlan_ofport,
            enable_sudo=False,
        )

        ovs_client.create_tun_port(
            vxlan_source_ip=local_ip, vxlan_udp_port=vxlan_udp_port
        )

        mock_shell_run.assert_called_once_with(
            command=[
                "/usr/bin/ovs-vsctl",
                "--may-exist",
                "add-port",
                "test_sw",
                "vxlan_out",
                "--",
                "set",
                "Interface",
                "vxlan_out",
                "type=vxlan",
                "options:in_key=flow",
                "options:out_key=flow",
                "options:remote_ip=flow",
                'options:local_ip="%s"' % local_ip,
                "options:dst_port=%d" % vxlan_udp_port,
                "ofport_request=%s" % vxlan_ofport,
            ],
            enable_sudo=False,
        )

    def test_sync_flows(self, mock_shell_run):
        file_name = "/tmp/flows.txt"
        switch_name = "test_sw"
        ovs_client = client.OvSClient(switch_name, file_name)
        writer = utils.MockWriter()

        with mock.patch(
            "%s.open" % client.__name__, mock.mock_open()
        ) as mock_file:
            mock_file.return_value.write = writer.write
            ovs_client.sync_flows(
                [
                    objects.OvsFlow(match="match1", action="action1"),
                    objects.OvsFlow(match="match2", action="action2"),
                ]
            )

        mock_file.assert_called_with(file_name, "w")

        assert writer.contents == "match1 action1\nmatch2 action2\n"

        mock_shell_run.assert_called_once_with(
            command=[
                "/usr/bin/ovs-ofctl",
                "-O",
                "OpenFlow13",
                "--bundle",
                "replace-flows",
                switch_name,
                file_name,
            ],
            enable_sudo=False,
        )
