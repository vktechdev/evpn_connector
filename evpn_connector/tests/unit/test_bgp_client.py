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

from evpn_connector.bgp import client
from evpn_connector.bgp.generated import gobgp_pb2
from evpn_connector.common import constants
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


class TestCountPeers(object):
    """A session being up is not the table having arrived."""

    @staticmethod
    def _peer(
        session_state=gobgp_pb2.PeerState.ESTABLISHED,
        uptime=1000,
        gr_received=True,
        end_of_rib_received=True,
    ):
        peer = gobgp_pb2.Peer()
        peer.state.session_state = session_state
        peer.timers.state.uptime.seconds = uptime
        afi_safi = peer.afi_safis.add()
        afi_safi.mp_graceful_restart.state.received = gr_received
        afi_safi.mp_graceful_restart.state.end_of_rib_received = (
            end_of_rib_received
        )
        return peer

    def _count(self, peers, settle_sec=0):
        responses = [mock.Mock(peer=peer) for peer in peers]
        fake_self = mock.Mock(
            list_peer=mock.Mock(return_value=responses),
            _peer_converged=client.BGPClient._peer_converged,
        )
        return client.BGPClient.count_peers(fake_self, settle_sec)

    def test_no_peers(self):
        assert self._count([]) == (0, 0)

    def test_established_with_end_of_rib(self):
        assert self._count([self._peer()]) == (1, 1)

    def test_established_while_the_table_is_still_coming(self):
        """The window fail-static exists for: session up, RIB half-read."""
        assert self._count([self._peer(end_of_rib_received=False)]) == (1, 0)

    def test_not_established(self):
        peer = self._peer(session_state=gobgp_pb2.PeerState.OPENSENT)
        assert self._count([peer]) == (1, 0)

    def test_without_graceful_restart_nothing_reports_the_end(self):
        """No End-of-RIB to wait for, so a fresh session is not trusted."""
        peer = self._peer(gr_received=False, end_of_rib_received=False)
        with mock.patch("time.time", return_value=1005):
            assert self._count([peer], settle_sec=10) == (1, 0)
            peer.timers.state.uptime.seconds = 990
            assert self._count([peer], settle_sec=10) == (1, 1)

    def test_a_session_younger_than_the_settle_time(self):
        peer = self._peer()
        with mock.patch("time.time", return_value=1005):
            assert self._count([peer], settle_sec=10) == (1, 0)

    def test_an_unset_uptime_is_not_trusted(self):
        peer = self._peer(uptime=0)
        with mock.patch("time.time", return_value=1005):
            assert self._count([peer], settle_sec=10) == (1, 0)


class TestVtepSources(object):
    @pytest.mark.parametrize(
        "route_type",
        [
            constants.EVPN_MACADV_TYPE,
            constants.EVPN_MULTICAST_TYPE,
            constants.EVPN_PREFIX_TYPE,
        ],
    )
    def test_all_paths_supply_vtep_sources(self, route_type):
        bgp = client.BGPClient("127.0.0.1:50051", 1, "02:00:00:00:00:01")
        common = dict(
            vni=10000,
            as_number=65001,
            next_hop="10.10.10.2",
            rt=objects.RouteTarget([(65001, 10000)]),
        )
        if route_type == constants.EVPN_MULTICAST_TYPE:
            route = objects.VirtNet(**common)
            prepare = bgp.prepare_multicast_path
        else:
            common.update(
                mac="02:00:00:00:00:02", ofport=65278, port_type="vxlan", tag=0
            )
            if route_type == constants.EVPN_MACADV_TYPE:
                route = objects.ClientEdge(ip="10.100.0.1", **common)
                prepare = bgp.prepare_unicast_path
            else:
                route = objects.ClientEdgePrefix(
                    prefix="10.100.0.1",
                    prefix_len=32,
                    router_mac="02:00:00:00:00:03",
                    **common,
                )
                prepare = bgp.prepare_prefix_path
        first = prepare(route)
        route.next_hop = "10.10.10.3"
        second = prepare(route)
        destination = gobgp_pb2.Destination(paths=[first, second])
        response = gobgp_pb2.ListPathResponse(destination=destination)
        bgp._get_paths_from_gobgp = mock.Mock(
            side_effect=(
                lambda prefix_type: (
                    [response] if prefix_type == route_type else []
                )
            )
        )
        bgp.get_paths(local_next_hop="10.10.10.1")
        assert bgp.vtep_addresses == {"10.10.10.2", "10.10.10.3"}
        route.next_hop = "10.10.10.4"
        destination.ClearField("paths")
        destination.paths.add().CopyFrom(prepare(route))
        response.destination.CopyFrom(destination)
        bgp.get_paths(local_next_hop="10.10.10.1")
        assert bgp.vtep_addresses == {"10.10.10.4"}
        bgp._get_paths_from_gobgp = mock.Mock(return_value=[])
        bgp.get_paths(local_next_hop="10.10.10.1")
        assert not bgp.vtep_addresses
