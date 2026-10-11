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

from evpn_connector.common import conf_opts
from evpn_connector.common import constants
from evpn_connector.service import evpn
from evpn_connector.service import objects


@pytest.fixture
def service(tmp_path):
    return evpn.EvpnConnectorService(
        source_ip="10.10.10.1",
        as_number=65001,
        configs_dir=str(tmp_path),
        gobgp_client=mock.MagicMock(),
        ovs_client=mock.MagicMock(),
        sender=mock.MagicMock(),
        vxlan_udp_port=4789,
        router_mac_type5="02:00:00:00:00:01",
        anycast_status_file=str(tmp_path / "anycast"),
        anycast_check_ofport=65277,
        anycast_check_mac="02:00:00:00:00:02",
        policy_enabled=False,
        fail_static=True,
    )


def prefix(source, address="10.100.0.1"):
    return objects.ClientEdgePrefix(
        mac="02:00:00:00:00:01",
        prefix=address,
        prefix_len=32,
        router_mac="02:00:00:00:00:02",
        vni=10000,
        as_number=65001,
        next_hop=source,
        rt=objects.RouteTarget([(65001, 10000)]),
        ofport=10,
        port_type="flat",
        tag=0,
    )


def ingress(flows):
    return {
        flow
        for flow in flows
        if "table=0" in flow.match.split(",")
        and ("in_port=%d" % constants.VXLAN_PORT_OFPORT)
        in flow.match.split(",")
    }


@pytest.mark.parametrize("restrict", [False, True])
def test_step_restricts_sources_from_every_evpn_route_type(service, restrict):
    assert service.restrict_tunnel_sources is False
    service.restrict_tunnel_sources = restrict
    local = prefix(service.source_ip)
    remote = prefix("10.10.10.2", "10.100.0.2")
    edge = objects.ClientEdge(
        mac="02:00:00:00:00:03",
        ip="",
        as_number=65001,
        vni=10001,
        next_hop="10.10.10.3",
        rt=objects.RouteTarget([(65001, 10001)]),
        ofport=65278,
        port_type="vxlan",
        tag=0,
    )
    vnet = objects.VirtNet(
        vni=10002,
        next_hop="10.10.10.4",
        as_number=65001,
        rt=objects.RouteTarget([(65001, 10002)]),
    )
    service.read_client_configs = mock.Mock(return_value=(set(), [local]))
    service._vrfs = {objects.VRF(10000, local.rt)}
    service.gobgp_client.get_paths.return_value = (
        set(),
        set(),
        {edge},
        {vnet},
        {local},
        {remote},
    )
    service.gobgp_client.count_peers.return_value = (1, 1)
    service.gobgp_client.vtep_addresses = {
        service.source_ip,
        "10.10.10.2",
        "10.10.10.3",
        "10.10.10.4",
    }
    service._step()
    flows = service.ovs_client.sync_flows.call_args[0][0]
    tunnel = ingress(flows)
    assert tunnel
    if not restrict:
        assert all("tun_src=" not in f.match for f in tunnel)
        return
    assert {
        next(
            field
            for field in flow.match.split(",")
            if field.startswith("tun_src=")
        )
        for flow in tunnel
    } == {
        "tun_src=10.10.10.2",
        "tun_src=10.10.10.3",
        "tun_src=10.10.10.4",
    }
    assert service._last_good_flows == flows
    service._sender.send_counter.assert_any_call("ovs_flow_cnt", len(flows))


def test_sources_withdraw_and_survive_rr_failure_and_restart(
    service, tmp_path
):
    service.restrict_tunnel_sources = True
    local = prefix(service.source_ip)
    remote = prefix("10.10.10.2", "10.100.0.2")
    service.read_client_configs = mock.Mock(return_value=(set(), [local]))
    service._vrfs = {objects.VRF(10000, local.rt)}
    service.gobgp_client.count_peers.return_value = (1, 1)
    service.gobgp_client.get_paths.return_value = (
        set(),
        set(),
        set(),
        set(),
        {local},
        {remote},
    )
    service.gobgp_client.vtep_addresses = {service.source_ip, remote.next_hop}
    service._step()
    saved = service.ovs_client.sync_flows.call_args[0][0]
    assert ingress(saved)
    assert all("tun_src=10.10.10.2" in f.match for f in ingress(saved))
    flow_file = tmp_path / "flows"
    flow_file.write_text("\n".join(f.to_string() for f in sorted(saved)))
    service.ovs_client.tmp_flow_file_path = str(flow_file)
    service._last_good_flows = service._read_synced_flows()
    service.gobgp_client.count_peers.return_value = (1, 0)
    service.gobgp_client.get_paths.return_value = (
        set(),
        set(),
        set(),
        set(),
        {local},
        set(),
    )
    service.gobgp_client.vtep_addresses = {service.source_ip}
    service._step()
    held = service.ovs_client.sync_flows.call_args[0][0]
    assert ingress(held) == ingress(saved)
    service.gobgp_client.count_peers.return_value = (1, 1)
    service._step()
    withdrawn = service.ovs_client.sync_flows.call_args[0][0]
    assert not ingress(withdrawn)
    assert any("in_port=10" in f.match for f in withdrawn)


def test_source_restriction_is_disabled_by_default(service):
    option = next(
        option
        for option in conf_opts.ovs_opts
        if option.name == "restrict_tunnel_sources"
    )
    assert option.default is False
    assert service.restrict_tunnel_sources is False


def test_source_rules_grow_with_vteps_instead_of_classifiers():
    classifiers = {
        objects.OvsFlow(
            "table=0,priority=10,in_port=65278,tun_id=%d" % vni,
            "actions=set_field:%d->reg2,resubmit(,1)" % vni,
        )
        for vni in range(10000, 10100)
    }
    sources = {"10.10.10.%d" % n for n in range(2, 22)}
    result = objects.restrict_tunnel_sources(classifiers, sources)
    assert len(ingress(result)) == len(sources)
    classified = {f for f in result if "table=3" in f.match.split(",")}
    assert len(classified) == len(classifiers) + 1
    assert len(result) == len(classifiers) + len(sources) + 1
    assert objects.restrict_tunnel_sources(result, set()) == result


@pytest.mark.parametrize("restrict", [False, True])
def test_legacy_snapshot_cannot_bypass_enabled_filter(
    service, tmp_path, restrict
):
    service.restrict_tunnel_sources = restrict
    broad = objects.OvsFlow(
        "table=0,priority=10,in_port=65278,tun_id=10000",
        "action=resubmit(,1)",
    )
    qualified = objects.OvsFlow(
        broad.match + ",tun_src=10.10.10.2", broad.action
    )
    local = objects.OvsFlow("table=0,in_port=10", "action=resubmit(,1)")
    saved = {broad, qualified, local}
    path = tmp_path / "flows"
    path.write_text("\n".join(flow.to_string() for flow in saved))
    service.ovs_client.tmp_flow_file_path = str(path)
    service._last_good_flows = service._read_synced_flows()
    service.gobgp_client.count_peers.return_value = (1, 0)
    result = service._apply_fail_static({local}, {}, False)
    expected = (
        objects.restrict_tunnel_sources(saved, set()) if restrict else saved
    )
    assert result == expected
    if restrict:
        assert {f.to_string() for f in ingress(result)} == {
            "table=0,priority=10,in_port=65278,tun_src=10.10.10.2 "
            "actions=resubmit(,3)"
        }


@pytest.mark.parametrize(
    "match",
    [
        "table=0,priority=10,in_port=65278,tun_id=10000",
        "table=0,priority=11,in_port=65278,tun_id=10000,ip,nw_src=10.100.0.1",
        "table=0,priority=10,in_port=65278,tun_id=10000,arp",
    ],
)
def test_every_tunnel_classifier_keeps_its_actions(match):
    action = (
        "actions=move:NXM_NX_TUN_GBP_ID[]->NXM_NX_PKT_MARK[0..15],resubmit(,1)"
    )
    original = objects.OvsFlow(match, action)
    local = objects.OvsFlow(
        "table=0,priority=10,in_port=10", "actions=output:11"
    )
    recirculated = objects.OvsFlow(
        "table=1,priority=10,in_port=65278", "actions=output:10"
    )
    flows = {original, local, recirculated, objects.OvsDropFlow(0)}
    result = objects.restrict_tunnel_sources(
        flows, {"10.10.10.2", "2001:db8::2"}
    )
    assert local in result and recirculated in result
    assert original not in result
    assert {f.to_string() for f in ingress(result)} == {
        "table=0,priority=10,in_port=65278,tun_src=10.10.10.2 "
        "actions=resubmit(,3)",
        "table=0,priority=10,in_port=65278,tun_ipv6_src=2001:db8::2 "
        "actions=resubmit(,3)",
    }
    classified = objects.OvsFlow(match.replace("table=0", "table=3"), action)
    assert classified in result
    assert next(f for f in result if f == classified).action == action
    empty = objects.restrict_tunnel_sources(flows, set())
    assert not ingress(empty)
    assert empty == flows - {original} | {classified, objects.OvsDropFlow(3)}


def test_unqualified_legacy_snapshot_cannot_admit_sources(service):
    service.restrict_tunnel_sources = True
    service.gobgp_client.count_peers.return_value = (1, 0)
    service._last_good_flows = {
        objects.OvsFlow(
            "table=0,priority=10,in_port=65278,tun_id=10000",
            "actions=resubmit(,1)",
        )
    }
    result = service._apply_fail_static({objects.OvsDropFlow(0)}, {}, False)
    assert not ingress(result)
    assert objects.OvsDropFlow(0) in result
    assert objects.OvsDropFlow(3) in result
