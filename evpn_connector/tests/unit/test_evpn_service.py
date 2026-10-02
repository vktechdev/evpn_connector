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
import pytest
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

    def setup_method(self, method):
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self, method):
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


class TestFailStatic(object):
    def _make_service(
        self,
        fail_static=True,
        fail_static_min_peers=0,
        step_period=5,
    ):
        return evpn.EvpnConnectorService(
            source_ip="10.10.10.1",
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
            fail_static=fail_static,
            fail_static_min_peers=fail_static_min_peers,
            step_period=step_period,
        )

    def test_snapshot_survives_a_restart(self, tmpdir):
        """A restart while the RR is down keeps the synced flows."""
        flow_file = tmpdir.join("flows")
        flow_file.write("match-a actions=NORMAL\nmatch-b actions=drop\n")

        service = self._make_service()
        service.ovs_client.tmp_flow_file_path = str(flow_file)
        service._setup()

        assert {f.to_string() for f in service._last_good_flows} == {
            "match-a actions=NORMAL",
            "match-b actions=drop",
        }

    def test_no_flow_file_yet_is_an_empty_snapshot(self, tmpdir):
        service = self._make_service()
        service.ovs_client.tmp_flow_file_path = str(tmpdir.join("absent"))
        service._setup()

        assert service._last_good_flows == set()

    def test_a_retained_flow_read_back_is_the_flow_it_was(self, tmpdir):
        """A flow read back merges with the same flow from the RIB."""
        flow_file = tmpdir.join("flows")
        flow_file.write("match-a actions=NORMAL\n")

        service = self._make_service()
        service.ovs_client.tmp_flow_file_path = str(flow_file)
        service._setup()
        service.gobgp_client.count_peers.return_value = (2, 0)

        fresh = objects.OvsFlow("match-a", "actions=NORMAL")
        result = service._apply_fail_static({fresh}, {}, True)

        assert result == {fresh}

    def test_peers_healthy_all_established(self):
        service = self._make_service()
        service.gobgp_client.count_peers.return_value = (2, 2)

        assert service._upstream_peers_healthy() is True

    def test_peers_degraded_no_peers(self):
        """An empty peer list is a restarted gobgp, not a healthy node.

        It is indistinguishable from every session having been lost, and
        it comes with an empty RIB, which is precisely the set of flows
        that must not be trusted for deletion.
        """
        service = self._make_service()
        service.gobgp_client.count_peers.return_value = (0, 0)

        assert service._upstream_peers_healthy() is False

    def test_no_peers_past_settle_is_healthy(self):
        service = self._make_service()
        service.gobgp_client.count_peers.return_value = (0, 0)

        with mock.patch.object(evpn.time, "time", return_value=100):
            assert service._upstream_peers_healthy() is False
        with mock.patch.object(evpn.time, "time", return_value=110):
            assert service._upstream_peers_healthy() is True

    def test_peers_appearing_restart_the_settle(self):
        service = self._make_service()
        service.gobgp_client.count_peers.return_value = (0, 0)
        with mock.patch.object(evpn.time, "time", return_value=100):
            service._upstream_peers_healthy()
        service.gobgp_client.count_peers.return_value = (1, 1)
        service._upstream_peers_healthy()
        service.gobgp_client.count_peers.return_value = (0, 0)

        with mock.patch.object(evpn.time, "time", return_value=110):
            assert service._upstream_peers_healthy() is False

    def test_restart_without_peers_drops_the_read_back_flows(self, tmpdir):
        flow_file = tmpdir.join("flows")
        flow_file.write("match-a actions=NORMAL\n")
        service = self._make_service()
        service.ovs_client.tmp_flow_file_path = str(flow_file)
        service._setup()
        service.gobgp_client.count_peers.return_value = (0, 0)

        with mock.patch.object(evpn.time, "time", return_value=100):
            service._upstream_peers_healthy()
        with mock.patch.object(evpn.time, "time", return_value=110):
            result = service._apply_fail_static(set(), {}, True)

        assert result == set()

    def test_apply_without_a_snapshot_changes_nothing(self):
        """A node that never had peers is not held back by fail-static."""
        service = self._make_service()
        service.gobgp_client.count_peers.return_value = (0, 0)
        metrics = {}

        result = service._apply_fail_static({"flow-a"}, metrics, True)

        assert result == {"flow-a"}
        assert metrics["fail_static_retained_cnt"] == 0

    def test_peers_degraded_partial(self):
        service = self._make_service()
        service.gobgp_client.count_peers.return_value = (2, 1)

        assert service._upstream_peers_healthy() is False

    def test_min_peers_allows_a_partial_fabric(self):
        service = self._make_service(fail_static_min_peers=1)
        service.gobgp_client.count_peers.return_value = (3, 1)

        assert service._upstream_peers_healthy() is True

    def test_min_peers_still_degrades_below_the_threshold(self):
        service = self._make_service(fail_static_min_peers=2)
        service.gobgp_client.count_peers.return_value = (3, 1)

        assert service._upstream_peers_healthy() is False

    def test_min_peers_above_configured_means_all_of_them(self):
        service = self._make_service(fail_static_min_peers=5)
        service.gobgp_client.count_peers.return_value = (2, 2)

        assert service._upstream_peers_healthy() is True

    def test_unreadable_peers_raise(self):
        """A local gobgp fault is an error, not a held state.

        It is indistinguishable from a broken fabric, and the step that
        raises never reaches sync_flows, so flows are retained anyway.
        """
        service = self._make_service()
        service.gobgp_client.count_peers.side_effect = RuntimeError("boom")

        with pytest.raises(RuntimeError):
            service._upstream_peers_healthy()

    def test_apply_raises_and_keeps_the_snapshot_on_error(self):
        service = self._make_service()
        metrics = {}
        service.gobgp_client.count_peers.return_value = (1, 1)
        service._apply_fail_static({"flow-a"}, metrics, True)
        service.gobgp_client.count_peers.side_effect = RuntimeError("boom")

        with pytest.raises(RuntimeError):
            service._apply_fail_static({"flow-b"}, metrics, True)

        assert service._last_good_flows == {"flow-a"}

    def test_apply_healthy_snapshots_and_passes_through(self):
        service = self._make_service()
        service.gobgp_client.count_peers.return_value = (1, 1)
        metrics = {}
        target = {"flow-a", "flow-b"}

        result = service._apply_fail_static(target, metrics, True)

        assert result == target
        assert service._last_good_flows == target
        assert metrics["fail_static_active"] == 0
        assert metrics["fail_static_retained_cnt"] == 0

    def test_apply_degraded_retains_last_good(self):
        service = self._make_service()
        metrics = {}
        # Healthy step snapshots two flows
        service.gobgp_client.count_peers.return_value = (1, 1)
        service._apply_fail_static({"flow-a", "flow-remote"}, metrics, True)
        # Peer lost: remote flow vanished from the computed set
        service.gobgp_client.count_peers.return_value = (1, 0)

        result = service._apply_fail_static({"flow-a"}, metrics, True)

        assert result == {"flow-a", "flow-remote"}
        # Snapshot must not be overwritten by the degraded set
        assert service._last_good_flows == {"flow-a", "flow-remote"}
        assert metrics["fail_static_active"] == 1
        assert metrics["fail_static_retained_cnt"] == 1

    def test_apply_degraded_still_applies_local_changes(self):
        service = self._make_service()
        metrics = {}
        service.gobgp_client.count_peers.return_value = (1, 1)
        service._apply_fail_static({"flow-remote"}, metrics, True)
        service.gobgp_client.count_peers.return_value = (1, 0)

        result = service._apply_fail_static({"flow-new-local"}, metrics, True)

        assert result == {"flow-remote", "flow-new-local"}

    def test_apply_recovery_drops_stale_flows(self):
        service = self._make_service()
        metrics = {}
        service.gobgp_client.count_peers.return_value = (1, 1)
        service._apply_fail_static({"flow-a", "flow-remote"}, metrics, True)
        service.gobgp_client.count_peers.return_value = (1, 0)
        service._apply_fail_static({"flow-a"}, metrics, True)
        # Peer is back; RIB is authoritative again
        service.gobgp_client.count_peers.return_value = (1, 1)

        result = service._apply_fail_static({"flow-a"}, metrics, True)

        assert result == {"flow-a"}
        assert service._last_good_flows == {"flow-a"}
        assert metrics["fail_static_active"] == 0

    def test_apply_degraded_keeps_the_fresh_action_for_a_known_match(self):
        """What makes retention safe: a stale flow never wins a match.

        Flows are equal by match alone, and a union keeps the side it
        started from, so a match that is still computed is applied with
        its current action and only matches that vanished are retained.
        """
        service = self._make_service()
        metrics = {}
        stale = objects.OvsFlow(
            match="table=0,priority=10,in_port=1", action="action=output:5"
        )
        service.gobgp_client.count_peers.return_value = (1, 1)
        service._apply_fail_static({stale}, metrics, True)
        fresh = objects.OvsFlow(
            match="table=0,priority=10,in_port=1", action="action=output:9"
        )
        service.gobgp_client.count_peers.return_value = (1, 0)

        result = service._apply_fail_static({fresh}, metrics, True)

        assert [flow.to_string() for flow in result] == [fresh.to_string()]
        assert metrics["fail_static_retained_cnt"] == 0

    def test_health_before_the_rib_read_counts_too(self):
        """A peer that converged mid-step leaves a half-read RIB.

        The second sample alone would call that set authoritative and
        snapshot it, which is the very set fail-static exists to
        distrust.
        """
        service = self._make_service()
        metrics = {}
        service.gobgp_client.count_peers.return_value = (1, 1)
        service._apply_fail_static({"flow-a", "flow-remote"}, metrics, True)
        # Healthy now, but it was not when the RIB was read
        result = service._apply_fail_static({"flow-a"}, metrics, False)

        assert result == {"flow-a", "flow-remote"}
        assert service._last_good_flows == {"flow-a", "flow-remote"}
        assert metrics["fail_static_active"] == 1

    def test_settle_time_defaults_to_two_steps(self):
        service = self._make_service(step_period=7)
        service.gobgp_client.count_peers.return_value = (1, 1)

        service._upstream_peers_healthy()

        service.gobgp_client.count_peers.assert_called_once_with(14)

    def test_disabled_passes_through_when_degraded(self):
        service = self._make_service(fail_static=False)
        metrics = {}
        service.gobgp_client.count_peers.return_value = (1, 0)

        result = service._apply_fail_static({"flow-a"}, metrics, True)

        assert result == {"flow-a"}
        service.gobgp_client.count_peers.assert_not_called()
