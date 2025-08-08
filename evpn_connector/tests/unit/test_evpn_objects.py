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

import sys

from evpn_connector.common import constants
from evpn_connector.service import objects


class TestEvpnConnectorObjects(object):
    def test_ovs_flow(self):
        match1 = "table=1,priority=100"
        match2 = "table=1,priority=200"
        action1 = "actions=output:1"
        action2 = "actions=output:2"
        flow1 = objects.OvsFlow(match=match1, action=action1)
        flow2 = objects.OvsFlow(match=match1, action=action2)
        flow3 = objects.OvsFlow(match=match2, action=action2)

        assert flow1 == flow2
        assert flow1 < flow3
        assert sorted([flow1, flow2, flow3]) == [flow1, flow2, flow3]
        assert {flow1, flow1, flow2, flow3} == {flow1, flow2, flow3}

    def test_client_edge(self):
        common_fields1 = {
            "mac": "d8:6b:5c:cd:97:ee",
            "vni": 1,
            "ip": "192.168.1.1",
            "rt": objects.RouteTarget(targets=[(65001, 100)]),
        }

        common_fields2 = {
            "mac": "d8:6b:5c:cd:97:ed",
            "vni": 2,
            "ip": "192.168.1.2",
            "rt": objects.RouteTarget(targets=[(65002, 200)]),
        }

        ce1 = objects.ClientEdge(
            as_number=65001,
            ofport=1,
            port_type="vxlan",
            tag=100,
            next_hop="some_ip",
            **common_fields1
        )

        ce2 = objects.ClientEdge(
            as_number=65001,
            ofport=2,
            port_type="flat",
            tag=200,
            next_hop="another_ip",
            **common_fields1
        )

        ce3 = objects.ClientEdge(
            as_number=65002,
            ofport=2,
            port_type="flat",
            tag=300,
            next_hop="another_ip",
            **common_fields2
        )

        # comparison only by mac, ip, vni and rt
        assert ce1 == ce2
        assert ce1 < ce3
        assert sorted([ce1, ce2, ce3]) == [ce1, ce2, ce3]
        assert {ce1, ce1, ce2, ce3} == {ce1, ce2, ce3}

    def test_client_edge_prefix_anycast(self):
        common_fields1 = {
            "prefix": "1.1.1.1",
            "prefix_len": 32,
            "mac": "d8:6b:5c:cd:97:ee",
            "vni": 1,
            "rt": objects.RouteTarget(targets=[(65001, 100)]),
            "router_mac": "11:22:33:44:55:66",
            "anycast_check_ofport": 65277,
            "anycast_check_mac": "12:34:56:78:90:aa",
            "dst_ip": "1.1.1.10",
            "check_ip": "1.1.1.20",
            "internal_dst_ip": "2.2.2.2",
            "internal_checker_ip": "2.2.2.3",
            "conntrack_zone": 100,
        }

        common_fields2 = {
            "prefix": "1.1.1.2",
            "prefix_len": 32,
            "mac": "d8:6b:5c:cd:97:ed",
            "vni": 2,
            "rt": objects.RouteTarget(targets=[(65002, 200)]),
            "router_mac": "11:22:33:44:55:66",
            "anycast_check_ofport": 65277,
            "anycast_check_mac": "12:34:56:78:90:aa",
            "dst_ip": "1.1.1.10",
            "check_ip": "1.1.1.20",
            "internal_dst_ip": "2.2.2.2",
            "internal_checker_ip": "2.2.2.3",
            "conntrack_zone": 100,
        }

        pr1 = objects.ClientEdgePrefixAnycast(
            as_number=65001,
            ofport=1,
            port_type="vxlan",
            tag=100,
            next_hop="10.10.10.1",
            **common_fields1
        )

        pr2 = objects.ClientEdgePrefixAnycast(
            as_number=65001,
            ofport=2,
            port_type="vxlan",
            tag=200,
            next_hop="10.10.10.1",
            **common_fields1
        )

        pr3 = objects.ClientEdgePrefixAnycast(
            as_number=65001,
            ofport=3,
            port_type="vxlan",
            tag=300,
            next_hop="10.10.10.3",
            **common_fields2
        )

        assert pr1 == pr2
        assert pr1 < pr3
        assert sorted([pr1, pr2, pr3]) == [pr1, pr2, pr3]
        assert {pr1, pr1, pr3, pr3} == {pr1, pr2, pr3}

    def test_client_edge_prefix(self):
        common_fields1 = {
            "prefix": "1.1.1.1",
            "prefix_len": 32,
            "mac": "d8:6b:5c:cd:97:ee",
            "vni": 1,
            "rt": objects.RouteTarget(targets=[(65001, 100)]),
            "router_mac": "11:22:33:44:55:66",
        }

        common_fields2 = {
            "prefix": "1.1.1.1",
            "prefix_len": 32,
            "mac": "d8:6b:5c:cd:97:ed",
            "vni": 2,
            "rt": objects.RouteTarget(targets=[(65002, 200)]),
            "router_mac": "11:22:33:44:55:66",
        }

        pr1 = objects.ClientEdgePrefix(
            as_number=65001,
            ofport=1,
            port_type="vxlan",
            tag=100,
            next_hop="10.10.10.1",
            **common_fields1
        )

        pr2 = objects.ClientEdgePrefix(
            as_number=65001,
            ofport=2,
            port_type="vxlan",
            tag=200,
            next_hop="10.10.10.1",
            **common_fields1
        )

        pr3 = objects.ClientEdgePrefix(
            as_number=65001,
            ofport=3,
            port_type="vxlan",
            tag=300,
            next_hop="10.10.10.3",
            **common_fields2
        )

        assert pr1 == pr2
        assert pr1 < pr3
        assert sorted([pr1, pr2, pr3]) == [pr1, pr2, pr3]
        assert {pr1, pr1, pr3, pr3} == {pr1, pr2, pr3}

    def test_virt_net(self):
        common_fields1 = {
            "vni": 1,
            "next_hop": "192.168.1.1",
            "rt": objects.RouteTarget(targets=[(65001, 100)]),
        }

        common_fields2 = {
            "vni": 2,
            "next_hop": "192.168.1.2",
            "rt": objects.RouteTarget(targets=[(65002, 200)]),
        }

        vn1 = objects.VirtNet(as_number=65001, **common_fields1)
        vn2 = objects.VirtNet(as_number=65001, **common_fields1)
        vn3 = objects.VirtNet(as_number=65002, **common_fields2)

        # comparison only by vni, next_hop and rt
        assert vn1 == vn2
        assert vn1 < vn3
        assert sorted([vn1, vn2, vn3]) == [vn1, vn2, vn3]
        assert {vn1, vn1, vn2, vn3} == {vn1, vn2, vn3}

    def test_route_target(self):
        rt1 = objects.RouteTarget(
            targets={(65001, 100), (65222, 200), (65003, 300)}
        )
        rt2 = objects.RouteTarget(
            targets={(65222, 200), (65001, 100), (65003, 300)}
        )
        rt3 = objects.RouteTarget(
            targets={(65333, 300), (65001, 100), (65003, 300)}
        )

        assert rt1 == rt2
        if sys.version_info[0] < 3:
            assert rt1 < rt3
            assert sorted([rt1, rt2, rt3]) == [rt1, rt2, rt3]
        else:
            assert rt1 > rt3
            assert sorted([rt1, rt2, rt3]) == [rt3, rt2, rt1]
        assert {rt1, rt1, rt2, rt3} == {rt1, rt2, rt3}

    def test_ovs_reg_match(self):
        mac = "d8:6b:5c:cd:97:ee"
        vni = 10
        ce = objects.ClientEdge(
            mac=mac,
            vni=vni,
            ip="",
            as_number=1,
            rt=objects.RouteTarget(targets=[(65001, 100)]),
            ofport=1,
            port_type="vxlan",
            tag=100,
            next_hop="192.168.1.2",
        )

        table = 1
        flow = ce._ovs_reg_match(local=True, table=table)
        assert flow == "table=%s,priority=%s,reg0=%s,dl_dst=%s" % (
            table,
            constants.NORMAL_PRIO,
            vni,
            mac,
        )

        flow = ce._ovs_reg_match()
        assert flow == "table=%s,priority=%s,reg0=%s,reg1=%s,dl_dst=%s" % (
            constants.OUTPUT_TABLE_NUM,
            constants.NORMAL_PRIO,
            vni,
            constants.REG_FROM_LOCAL,
            mac,
        )

    def test_vnet_from_ce(self):
        client_edges = [
            objects.ClientEdge(
                mac="d8:6b:5c:cd:97:ee",
                vni=1,
                ip="192.168.1.1",
                as_number=65001,
                rt=objects.RouteTarget(targets=[(65001, 100)]),
                ofport=1,
                port_type="vxlan",
                tag=100,
                next_hop="192.168.1.3",
            ),
            objects.ClientEdge(
                mac="28:63:5f:98:ba:0e",
                vni=1,
                rt=objects.RouteTarget(targets=[(65001, 100)]),
                as_number=65001,
                tag=100,
                ofport=2,
                port_type="vxlan",
                ip="192.168.1.2",
                next_hop="192.168.1.3",
            ),
            objects.ClientEdge(
                mac="28:63:5f:98:ba:0e",
                vni=2,
                rt=objects.RouteTarget(targets=[(65002, 200)]),
                as_number=65002,
                tag=200,
                ofport=3,
                port_type="vlan",
                ip="192.168.1.4",
                next_hop="192.168.1.5",
            ),
        ]

        vnet_vnis, vnets = objects.vnet_from_ce(client_edges)

        expected_vnets = {
            objects.VirtNet(
                1,
                objects.RouteTarget([(65001, 100)]),
                as_number=65001,
                next_hop="192.168.1.3",
            ),
            objects.VirtNet(
                2,
                objects.RouteTarget([(65002, 200)]),
                as_number=65002,
                next_hop="192.168.1.5",
            ),
        }
        expected_vnis = {1, 2}

        assert len(vnet_vnis) == len(vnets) == 2
        assert expected_vnets == vnets
        assert expected_vnis == vnet_vnis
