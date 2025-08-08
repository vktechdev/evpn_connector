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

import json
import mock
import os
import shutil
import tempfile

from evpn_connector.common import constants
from evpn_connector.service import evpn
from evpn_connector.service import objects


class TestEvpnConnectorService(object):
    def test_rt2lst_default(self):
        rt_list = {"1:100", "1:200", "1:100"}
        expected = {(1, 100), (1, 200), (1, 100)}

        assert evpn.EvpnConnectorService._rt2lst(rt_list) == expected

    def test_rt2lst_as_local_ovveride(self):
        rt_list = {"%s:100" % constants.RT_DEFAULT_FIRST_PART}
        as_local = 65555
        expected = {(as_local, 100)}

        assert (
            evpn.EvpnConnectorService._rt2lst(rt_list, local_asn=as_local)
            == expected
        )

    def setup(self):
        self.temp_dir = tempfile.mkdtemp()

    def teardown(self):
        shutil.rmtree(self.temp_dir)

    def test_read_client_configs_with_no_folder(self):
        evpn_service = evpn.EvpnConnectorService(
            source_ip="",
            as_number=1,
            configs_dir="",
            gobgp_client=mock.MagicMock(),
            ovs_client=mock.MagicMock(),
            sender=mock.MagicMock(),
            vxlan_udp_port=4789,
            router_mac_type5="11:22:33:44:55:66",
            anycast_status_file="/tmp/anycast_status_file",
            anycast_check_ofport=65277,
            anycast_check_mac="12:34:56:78:90:aa",
        )

        result = evpn_service.read_client_configs()

        assert result == (set(), [])

    def test_read_l2_client_configs(self):
        temp_folder = self.temp_dir

        sample_config = {
            "ofport": 33000,
            "mac": "36:e7:a5:00:00:01",
            "tag": 0,
            "exp_rt": ["1:10"],
            "imp_rt": ["1:10"],
            "ip": "192.168.111.2",
            "type": "flat",
            "vni": 10,
        }

        with open(
            os.path.join(temp_folder, "sample_l2_config.json"), "w"
        ) as f:
            json.dump(sample_config, f)

        service_src_ip = "10.10.10.2"
        service_as_number = 1

        evpn_service = evpn.EvpnConnectorService(
            source_ip=service_src_ip,
            as_number=service_as_number,
            configs_dir=temp_folder,
            gobgp_client=mock.MagicMock(),
            ovs_client=mock.MagicMock(),
            sender=mock.MagicMock(),
            vxlan_udp_port=4789,
            router_mac_type5="11:22:33:44:55:66",
            anycast_status_file="/tmp/anycast_status_file",
            anycast_check_ofport=65277,
            anycast_check_mac="12:34:56:78:90:aa",
        )

        res_ce, res_pr = evpn_service.read_client_configs()

        expected_ce = objects.ClientEdge(
            mac=sample_config["mac"],
            ip="",
            ofport=sample_config["ofport"],
            port_type=sample_config["type"],
            tag=sample_config["tag"],
            vni=sample_config["vni"],
            next_hop=service_src_ip,
            as_number=service_as_number,
            rt=objects.RouteTarget(targets=[(service_as_number, 10)]),
        )

        assert len(res_ce) == 1
        assert len(res_pr) == 0
        assert res_ce.pop() == expected_ce

    def test_read_l3_client_configs(self):
        temp_folder = self.temp_dir

        prefix = "192.168.111.2"
        prefix_len = 32
        router_mac = "11:22:33:44:55:66"

        sample_config = {
            "cfg_type": "l3",
            "ofport": 33000,
            "mac": "36:e7:a5:00:00:01",
            "tag": 0,
            "exp_rt": ["1:10"],
            "imp_rt": ["1:10"],
            "routes": ["%s/%d" % (prefix, prefix_len)],
            "type": "flat",
            "vni": 10,
        }

        with open(
            os.path.join(temp_folder, "sample_l3_config.json"), "w"
        ) as f:
            json.dump(sample_config, f)

        service_src_ip = "10.10.10.2"
        service_as_number = 1

        evpn_service = evpn.EvpnConnectorService(
            source_ip=service_src_ip,
            as_number=service_as_number,
            configs_dir=temp_folder,
            gobgp_client=mock.MagicMock(),
            ovs_client=mock.MagicMock(),
            sender=mock.MagicMock(),
            vxlan_udp_port=4789,
            router_mac_type5=router_mac,
            anycast_status_file="/tmp/anycast_status_file",
            anycast_check_ofport=65277,
            anycast_check_mac="12:34:56:78:90:aa",
        )

        res_ce, res_pr = evpn_service.read_client_configs()

        expected_pr = objects.ClientEdgePrefix(
            mac=sample_config["mac"],
            prefix=prefix,
            prefix_len=prefix_len,
            ofport=sample_config["ofport"],
            port_type=sample_config["type"],
            tag=sample_config["tag"],
            vni=sample_config["vni"],
            next_hop=service_src_ip,
            as_number=service_as_number,
            rt=objects.RouteTarget(targets=[(service_as_number, 10)]),
            router_mac=router_mac,
        )

        assert len(res_ce) == 0
        assert len(res_pr) == 1
        assert res_pr.pop() == expected_pr

    def test_read_l3_anycast_client_configs(self):
        temp_folder = self.temp_dir

        prefix = "192.168.111.2"
        prefix_len = 32
        router_mac = "11:22:33:44:55:66"

        anycast_ip1 = "192.168.111.10"
        anycast_ip2 = "192.168.111.11"
        check_ip = "192.168.111.100"
        internal_dst_ip = "172.12.0.2"
        internal_checker_ip = "172.12.0.1"
        conntrack_zone = 10001

        sample_config = {
            "cfg_type": "l3",
            "ofport": 33000,
            "mac": "36:e7:a5:00:00:01",
            "tag": 0,
            "exp_rt": ["1:10"],
            "imp_rt": ["1:10"],
            "routes": ["%s/%d" % (prefix, prefix_len)],
            "type": "flat",
            "vni": 10,
            "anycast": [
                {
                    "dst_ip": prefix,
                    "anycast_ip": anycast_ip1,
                    "check_ip": check_ip,
                    "internal_dst_ip": internal_dst_ip,
                    "internal_checker_ip": internal_checker_ip,
                    "conntrack_zone": conntrack_zone,
                },
                {
                    "dst_ip": prefix,
                    "anycast_ip": anycast_ip2,
                    "check_ip": check_ip,
                    "internal_dst_ip": internal_dst_ip,
                    "internal_checker_ip": internal_checker_ip,
                    "conntrack_zone": conntrack_zone,
                },
            ],
        }

        with open(
            os.path.join(temp_folder, "sample_l3_anycast_config.json"), "w"
        ) as f:
            json.dump(sample_config, f)

        service_src_ip = "10.10.10.2"
        service_as_number = 1

        evpn_service = evpn.EvpnConnectorService(
            source_ip=service_src_ip,
            as_number=service_as_number,
            configs_dir=temp_folder,
            gobgp_client=mock.MagicMock(),
            ovs_client=mock.MagicMock(),
            sender=mock.MagicMock(),
            vxlan_udp_port=4789,
            router_mac_type5=router_mac,
            anycast_status_file="/tmp/anycast_status_file",
            anycast_check_ofport=65277,
            anycast_check_mac="12:34:56:78:90:aa",
        )

        res_ce, res_pr = evpn_service.read_client_configs()

        expected_pr = objects.ClientEdgePrefix(
            mac=sample_config["mac"],
            prefix=prefix,
            prefix_len=prefix_len,
            ofport=sample_config["ofport"],
            port_type=sample_config["type"],
            tag=sample_config["tag"],
            vni=sample_config["vni"],
            next_hop=service_src_ip,
            as_number=service_as_number,
            rt=objects.RouteTarget(targets=[(service_as_number, 10)]),
            router_mac=router_mac,
        )

        expected_any_pr1 = objects.ClientEdgePrefixAnycast(
            mac=sample_config["mac"],
            prefix=anycast_ip1,
            prefix_len=prefix_len,
            ofport=sample_config["ofport"],
            port_type=sample_config["type"],
            tag=sample_config["tag"],
            vni=sample_config["vni"],
            next_hop=service_src_ip,
            as_number=service_as_number,
            rt=objects.RouteTarget(targets=[(service_as_number, 10)]),
            router_mac=router_mac,
            anycast_check_ofport=65277,
            anycast_check_mac="12:34:56:78:90:aa",
            dst_ip=prefix,
            check_ip=check_ip,
            internal_dst_ip=internal_dst_ip,
            internal_checker_ip=internal_checker_ip,
            conntrack_zone=conntrack_zone,
        )

        expected_any_pr2 = objects.ClientEdgePrefixAnycast(
            mac=sample_config["mac"],
            prefix=anycast_ip2,
            prefix_len=prefix_len,
            ofport=sample_config["ofport"],
            port_type=sample_config["type"],
            tag=sample_config["tag"],
            vni=sample_config["vni"],
            next_hop=service_src_ip,
            as_number=service_as_number,
            rt=objects.RouteTarget(targets=[(service_as_number, 10)]),
            router_mac=router_mac,
            anycast_check_ofport=65277,
            anycast_check_mac="12:34:56:78:90:aa",
            dst_ip=prefix,
            check_ip=check_ip,
            internal_dst_ip=internal_dst_ip,
            internal_checker_ip=internal_checker_ip,
            conntrack_zone=conntrack_zone,
        )

        assert len(res_ce) == 0
        assert len(res_pr) == 3
        assert expected_pr in res_pr
        assert expected_any_pr1 in res_pr
        assert expected_any_pr2 in res_pr
