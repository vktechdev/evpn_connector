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

from evpn_connector.bgp import client
from evpn_connector.service import objects


class TestBGPClient(object):
    def test_filter_local_announces(self):
        """Check that filter by next_hop works correctly"""

        common_conf = {
            "vni": 10,
            "as_number": 1,
            "rt": objects.RouteTarget(targets=[(65001, 100)]),
            "ofport": 3,
            "port_type": "vxlan",
            "tag": 0,
            "next_hop": "10.10.10.2",
        }

        another_hext_hop = "10.10.20.2"

        clients_edges = {
            objects.ClientEdge(mac="62:de:b1:b4:fd:15", ip="", **common_conf),
            objects.ClientEdge(mac="10:ac:c7:ef:c3:1b", ip="", **common_conf),
        }

        virt_nets = {
            objects.VirtNet(
                rt=common_conf["rt"],
                as_number=common_conf["as_number"],
                next_hop=common_conf["next_hop"],
                vni=common_conf["vni"],
            )
        }

        prefixes = {
            objects.ClientEdgePrefix(
                mac="62:de:b1:b4:fd:19",
                prefix="1.1.1.1",
                prefix_len=32,
                router_mac="11:22:33:44:55:66",
                **common_conf
            ),
            objects.ClientEdgePrefix(
                mac="12:de:b1:b4:fd:19",
                prefix="1.1.1.2",
                prefix_len=32,
                router_mac="11:22:33:44:55:66",
                **common_conf
            ),
        }

        objs = (clients_edges, virt_nets, prefixes)

        result = client.BGPClient.filter_local_announces(
            objs, common_conf["next_hop"]
        )

        (
            local_edges,
            local_virt_nets,
            remote_edges,
            remote_virt_nets,
            local_client_prefixes,
            remote_client_prefixes,
        ) = result

        assert local_edges == clients_edges
        assert local_virt_nets == virt_nets
        assert local_client_prefixes == prefixes
        assert not remote_edges
        assert not remote_virt_nets
        assert not remote_client_prefixes

        result = client.BGPClient.filter_local_announces(
            objs,
            another_hext_hop,
        )

        (
            local_edges,
            local_virt_nets,
            remote_edges,
            remote_virt_nets,
            local_client_prefixes,
            remote_client_prefixes,
        ) = result

        assert remote_edges == clients_edges
        assert remote_virt_nets == virt_nets
        assert remote_client_prefixes == prefixes
        assert not local_edges
        assert not local_virt_nets
        assert not local_client_prefixes

        remote_edge = {
            objects.ClientEdge(
                mac="a6:18:a7:79:7c:e2",
                next_hop=another_hext_hop,
                ip="",
                **{k: v for k, v in common_conf.items() if k != "next_hop"}
            )
        }

        result = client.BGPClient.filter_local_announces(
            (clients_edges.union(remote_edge), virt_nets, prefixes),
            common_conf["next_hop"],
        )

        (
            local_edges,
            local_virt_nets,
            remote_edges,
            remote_virt_nets,
            local_client_prefixes,
            remote_client_prefixes,
        ) = result

        assert local_edges == clients_edges
        assert local_virt_nets == virt_nets
        assert local_client_prefixes == prefixes
        assert remote_edges == remote_edge
        assert not remote_virt_nets
        assert not remote_client_prefixes

        remote_vnet = {
            objects.VirtNet(
                rt=common_conf["rt"],
                as_number=common_conf["as_number"],
                next_hop=another_hext_hop,
                vni=common_conf["vni"],
            )
        }

        result = client.BGPClient.filter_local_announces(
            (clients_edges, virt_nets.union(remote_vnet), prefixes),
            common_conf["next_hop"],
        )

        (
            local_edges,
            local_virt_nets,
            remote_edges,
            remote_virt_nets,
            local_client_prefixes,
            remote_client_prefixes,
        ) = result

        assert local_edges == clients_edges
        assert local_virt_nets == virt_nets
        assert local_client_prefixes == prefixes
        assert not remote_edges
        assert remote_virt_nets == remote_vnet
        assert not remote_client_prefixes
