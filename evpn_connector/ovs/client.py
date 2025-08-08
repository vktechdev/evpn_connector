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

from evpn_connector.common import constants
from evpn_connector.ovs import shell


OPENFLOW_PROTO_VERSIONS = ["OpenFlow13"]
VXLAN_PORT_NAME = "vxlan_out"
TUNNEL_TYPE = "vxlan"
DEFAULT_VXLAN_UDP_PORT = 4789

LOG = logging.getLogger(__name__)


class OvSClient(object):
    def __init__(
        self,
        sw_name,
        tmp_flow_file_path,
        vxlan_ofport=None,
        enable_sudo=False,
        ovsvsctl_bin=constants.OVSVSCTL_BIN,
        ovsofctl_bin=constants.OVSOFCTL_BIN,
    ):
        self.vxlan_ofport = vxlan_ofport or constants.VXLAN_PORT_OFPORT
        self.sw_name = sw_name
        self.enable_sudo = enable_sudo
        self.tmp_flow_file_path = tmp_flow_file_path
        self._vsctl_bin = ovsvsctl_bin
        self._ofctl_bin = ovsofctl_bin

    def create_bridge(self):
        cmd = [
            self._vsctl_bin,
            "--may-exist",
            "add-br",
            self.sw_name,
            "--",
            "set",
            "Bridge",
            self.sw_name,
            "protocols={}".format(",".join(OPENFLOW_PROTO_VERSIONS)),
            "fail-mode=secure",
        ]
        return shell.runsh(command=cmd, enable_sudo=self.enable_sudo)

    def create_tun_port(
        self,
        vxlan_source_ip,
        vxlan_udp_port=DEFAULT_VXLAN_UDP_PORT,
        port_name=VXLAN_PORT_NAME,
    ):
        cmd = [
            self._vsctl_bin,
            "--may-exist",
            "add-port",
            self.sw_name,
            port_name,
            "--",
            "set",
            "Interface",
            port_name,
            "type={}".format(TUNNEL_TYPE),
            "options:in_key=flow",
            "options:out_key=flow",
            "options:remote_ip=flow",
            'options:local_ip="{}"'.format(vxlan_source_ip),
            "options:dst_port={}".format(vxlan_udp_port),
            "ofport_request={}".format(self.vxlan_ofport),
        ]
        return shell.runsh(command=cmd, enable_sudo=self.enable_sudo)

    def sync_flows(self, flows):
        # Write data to tmp file
        data = ""
        for flow in sorted(flows):
            data += flow.to_string() + "\n"
        with open(self.tmp_flow_file_path, "w") as group_fl:
            group_fl.write(data)
        LOG.debug(
            "Successfull write %d bytes to tmp flow file %s",
            len(data),
            self.tmp_flow_file_path,
        )
        cmd = [
            self._ofctl_bin,
            "-O",
            OPENFLOW_PROTO_VERSIONS[0],
            "--bundle",
            "replace-flows",
            self.sw_name,
            self.tmp_flow_file_path,
        ]
        return shell.runsh(command=cmd, enable_sudo=self.enable_sudo)
