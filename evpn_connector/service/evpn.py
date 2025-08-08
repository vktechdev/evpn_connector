# vim: tabstop=4 shiftwidth=4 softtabstop=4
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


import copy
import json
import logging
import os
import time


from evpn_connector.common import constants
from evpn_connector.common.services import softirq
from evpn_connector.service import objects as evpnobj


LOG = logging.getLogger(__name__)
COMMON_NAME = "local-vni-"


def _rewrite_cfg_prefix(cfg, prefix):
    ncfg = copy.deepcopy(cfg)
    ncfg["prefix"], ncfg["prefix_len"] = prefix.strip().split("/")
    return ncfg


def _rewrite_anycast_params(cfg, acfg, check_ofport, check_mac):
    ncfg = copy.deepcopy(cfg)
    ncfg["prefix"] = acfg["anycast_ip"]
    # Anycast prefix must have /32 netmask always
    ncfg["prefix_len"] = 32
    ncfg["anycast_check_ofport"] = check_ofport
    ncfg["anycast_check_mac"] = check_mac
    ncfg["dst_ip"] = acfg["dst_ip"]
    ncfg["check_ip"] = acfg["check_ip"]
    ncfg["internal_dst_ip"] = acfg["internal_dst_ip"]
    ncfg["internal_checker_ip"] = acfg["internal_checker_ip"]
    ncfg["conntrack_zone"] = acfg["conntrack_zone"]
    return ncfg


def _anycast_to_str(internal_dst_ip, anycast_ip):
    return "%s_%s" % (anycast_ip, internal_dst_ip)


class EvpnConnectorService(softirq.SoftIrqServiceMetrics):
    def __init__(
        self,
        gobgp_client,
        ovs_client,
        source_ip,
        vxlan_udp_port,
        as_number,
        configs_dir,
        router_mac_type5,
        anycast_status_file,
        anycast_check_ofport,
        anycast_check_mac,
        sender,
        step_period=5,
        loop_period=0.5,
        event_type=None,
        error_event_type=None,
        policy_enabled=True,
    ):
        super(EvpnConnectorService, self).__init__(
            step_period=step_period,
            loop_period=loop_period,
            sender=sender,
            event_type=event_type,
            error_event_type=error_event_type,
        )
        self.configs_dir = configs_dir
        self.gobgp_client = gobgp_client
        self.ovs_client = ovs_client
        # Source ip for dataplane evpn traffic and next_hop for bgp announces
        self.source_ip = source_ip
        self.vxlan_udp_port = vxlan_udp_port
        self.as_number = as_number
        self._import_route_targets = set()
        self.policy_enabled = policy_enabled
        self.need_reset_peers = False
        self.router_mac_type5 = router_mac_type5
        self.anycast_status_file = anycast_status_file
        self.anycast_check_ofport = anycast_check_ofport
        self.anycast_check_mac = anycast_check_mac
        self.anycast_used = False

    def _setup(self):
        super(EvpnConnectorService, self)._setup()
        LOG.info("Create if not exist ovs switch and vxlan port")
        self.ovs_client.create_bridge()
        self.ovs_client.create_tun_port(
            vxlan_source_ip=self.source_ip, vxlan_udp_port=self.vxlan_udp_port
        )
        self.update_peer(force=True)

    @staticmethod
    def _rt2lst(rt_list, local_asn=None):
        # Convert RouteTarget from str repr "ASN:LABEL"
        res = set()
        for rt_str in rt_list:
            asn, label = rt_str.strip().split(":")
            if local_asn and asn == constants.RT_DEFAULT_FIRST_PART:
                asn = local_asn
            res.add((int(asn), int(label)))
        return res

    def read_client_configs(self):
        self._import_route_targets = set()
        self._vrfs = set()

        if not os.path.isdir(self.configs_dir):
            LOG.warning(
                "Not found directory with configs in %s", self.configs_dir
            )
            return set(), []

        # Use list for L3 configs because may be same prefixes in local configs
        # for ecmp
        res = {constants.CONFIG_L2_EVPN: set(), constants.CONFIG_L3_EVPN: []}
        used_ofports = set()
        confs_count = 0
        for fl_name in sorted(os.listdir(self.configs_dir)):
            path = os.path.join(self.configs_dir, fl_name)
            try:
                with open(path) as fl:
                    cfg = json.load(fl)

                    # Support old configs without type
                    cfg["cfg_type"] = cfg.get(
                        "cfg_type", constants.CONFIG_L2_EVPN
                    )
                    cf_type = cfg["cfg_type"]
                    if cf_type not in constants.SUPPORTED_CONFIG_TYPES:
                        LOG.error("Ingnore unknown config type: %s", str(cfg))
                        continue

                    # Ovs does not output traffic to the ingress port without
                    # the use of special actions - in_port. In this version,
                    # these actions are not used. Therefore, we check for
                    # uniqueness of the ofport
                    if cfg["ofport"] in used_ofports:
                        LOG.error(
                            "Ignore config with already used ofport: %s",
                            str(cfg),
                        )
                        continue
                    used_ofports.add(cfg["ofport"])

                    # For local ports next_hop is source_ip
                    cfg["next_hop"] = self.source_ip
                    cfg["rd_admin"] = self.as_number

                    # Convert RT to list format
                    cfg["imp_rt"] = self._rt2lst(
                        cfg["imp_rt"], local_asn=self.as_number
                    )
                    cfg["exp_rt"] = self._rt2lst(
                        cfg["exp_rt"], local_asn=self.as_number
                    )

                    # Create VRF from local_config if not exist
                    self._vrfs.add(evpnobj.VRF.from_dict(cfg))

                    if cf_type == constants.CONFIG_L2_EVPN:
                        # TODO(aleks.popov): See VKCSDEV-2728
                        cfg["ip"] = ""
                        res[cf_type].add(evpnobj.ClientEdge.from_dict(cfg))
                    elif cf_type == constants.CONFIG_L3_EVPN:
                        objs = []
                        cfg["router_mac"] = self.router_mac_type5
                        for route in cfg["routes"]:
                            # Create config for all routes with
                            # prefix = route prefix
                            objs.append(
                                evpnobj.ClientEdgePrefix.from_dict(
                                    _rewrite_cfg_prefix(cfg, route)
                                )
                            )
                        if "anycast" in cfg:
                            for acfg in cfg["anycast"]:
                                self.anycast_used = True
                                objs.append(
                                    evpnobj.ClientEdgePrefixAnycast.from_dict(
                                        _rewrite_anycast_params(
                                            cfg,
                                            acfg,
                                            self.anycast_check_ofport,
                                            self.anycast_check_mac,
                                        )
                                    )
                                )
                        res[cf_type] += objs

                    # We will keep the import route targets for further work
                    # with gobgp import policies
                    self._import_route_targets.update(
                        ((asn, num) for asn, num in cfg["imp_rt"])
                    )
                    confs_count += 1
            except Exception as err:
                LOG.exception(
                    "Failed to read config from %s: %s", path, str(err)
                )
        LOG.debug(
            "Read %d client confs from %s", confs_count, self.configs_dir
        )

        return res[constants.CONFIG_L2_EVPN], res[constants.CONFIG_L3_EVPN]

    def del_gobgp_object(self, obj):
        if type(obj) == evpnobj.DefinedSet:
            self.gobgp_client.delete_defined_set(obj)
        elif type(obj) == evpnobj.Statement:
            self.gobgp_client.delete_statement(obj)
        elif type(obj) == evpnobj.Policy:
            self.gobgp_client.delete_policy(obj)
        elif type(obj) == evpnobj.PolicyAssignment:
            self.gobgp_client.delete_policy_assignment(obj)

    def create_gobgp_object(self, obj):
        if type(obj) == evpnobj.DefinedSet:
            self.gobgp_client.add_defined_set(obj)
        elif type(obj) == evpnobj.Statement:
            self.gobgp_client.add_statement(obj)
        elif type(obj) == evpnobj.Policy:
            self.gobgp_client.add_policy(obj)
        elif type(obj) == evpnobj.PolicyAssignment:
            self.gobgp_client.add_policy_assignment(obj)

    def setup_target_state(
        self,
        name,
        imp_rt,
        defined_type=5,
        pa_name="global",
        pa_direction=1,
        pa_default_action=2,
    ):
        # If there are no route targets then do nothing
        if not imp_rt:
            return set()

        target_state = set()
        route_targets = ["rt:^%s:%s$" % (rt[0], rt[1]) for rt in imp_rt]
        def_set_name = name + "defined-set"
        defined_set = evpnobj.DefinedSet(
            defined_type, def_set_name, route_targets
        )
        target_state.add(defined_set)

        ext_comm_match_set = evpnobj.MatchSet(0, def_set_name)
        conditions = evpnobj.Conditions(ext_comm_match_set, -1)
        actions = evpnobj.Actions(1)
        statement_name = name + "statement"
        statement = evpnobj.Statement(statement_name, conditions, actions)
        target_state.add(statement)

        policy_name = name + "policy"
        policy = evpnobj.Policy(policy_name, [statement])
        target_state.add(policy)

        pa = evpnobj.PolicyAssignment(
            pa_name, pa_direction, [policy], pa_default_action
        )
        target_state.add(pa)
        return target_state

    def setup_current_state(
        self, name, defined_type=5, pa_name="global", pa_direction=1
    ):
        current_state = set()
        def_set_name = name + "defined-set"
        defined_set = self.gobgp_client.get_defined_set(
            defined_type, def_set_name
        )
        if defined_set:
            current_state.add(defined_set)

        statement_name = name + "statement"
        statement = self.gobgp_client.get_statement(statement_name)
        if statement:
            current_state.add(statement)

        policy_name = name + "policy"
        policy = self.gobgp_client.get_policy(policy_name)
        if policy:
            current_state.add(policy)

        pa = self.gobgp_client.get_policy_assignment(pa_name, pa_direction)
        if pa:
            current_state.add(pa)
        return current_state

    def sync_objects(self, target_state, current_state, add_func, del_func):
        objects_for_delete = current_state - target_state
        objects_for_create = target_state - current_state

        for obj in sorted(objects_for_delete, reverse=True):
            del_func(obj)
        for obj in sorted(objects_for_create):
            add_func(obj)

        return len(objects_for_create), len(objects_for_delete)

    def update_peer(
        self,
        peer_address="",  # "" - means all peers
        soft=True,
        direction=0,
        force=False,
    ):
        if not (force or self.need_reset_peers):
            return
        peers_responses = self.gobgp_client.list_peer(peer_address)
        if not peers_responses:
            LOG.warning("There are no peers!")
            self.need_reset_peers = True
            return
        for resp in peers_responses:
            self.gobgp_client.reset_peer(
                resp.peer.conf.neighbor_address, soft, direction
            )
            LOG.debug(
                "Done reset for peer: %s", resp.peer.conf.neighbor_address
            )
        self.need_reset_peers = False

    def get_anycast_status(self):
        if not os.path.isfile(self.anycast_status_file):
            LOG.warning(
                "Not found file with anycast statuses in %s",
                self.anycast_status_file,
            )
            return set()

        try:
            with open(self.anycast_status_file) as fl:
                statuses = set(json.load(fl))
        except Exception as err:
            LOG.exception(
                "Failed to read anycast statuses file from %s: %s",
                self.anycast_status_file,
                str(err),
            )
            return set()

        return statuses

    def _step(self):
        metrics = {}
        duration_metrics = {}

        LOG.debug("Start getting info from client configs")
        start_time = time.time()
        local_ce, local_prefixes = self.read_client_configs()
        local_vni_nums, local_vnet = evpnobj.vnet_from_ce(local_ce)
        local_l3_vni_nums = set((pr.vni for pr in local_prefixes))
        metrics["local_ce_cnt"] = len(local_ce)
        metrics["local_pr_cnt"] = len(local_prefixes)
        metrics["local_vni_cnt"] = len(local_vni_nums) + len(local_l3_vni_nums)
        duration_metrics["get_cfg_time"] = time.time() - start_time
        LOG.info(
            "Getting from configs done for %0.4f sec",
            duration_metrics["get_cfg_time"],
        )

        duration_metrics["update_policy_time"] = 0
        metrics["enabled_anycast_prefixes"] = 0
        metrics["disabled_anycast_prefixes"] = 0
        disabled_anycast_prefixes = []
        if self.anycast_used:
            LOG.debug("Actualize anycast prefix statuses")
            anycast_statuses = self.get_anycast_status()
            enabled_prefixes = []
            for prefix in local_prefixes:
                if prefix.is_anycast_prefix:
                    anycast_str = _anycast_to_str(
                        prefix.internal_dst_ip,
                        prefix.prefix,
                    )
                    if anycast_str in anycast_statuses:
                        metrics["enabled_anycast_prefixes"] += 1
                        enabled_prefixes.append(prefix)
                    else:
                        prefix.disabled = True
                        metrics["disabled_anycast_prefixes"] += 1
                        disabled_anycast_prefixes.append(prefix)
                else:
                    enabled_prefixes.append(prefix)
            local_prefixes = enabled_prefixes
            LOG.debug(
                "Found %d enabled and %d disabled anycast prefixes",
                metrics["enabled_anycast_prefixes"],
                metrics["disabled_anycast_prefixes"],
            )

        if self.policy_enabled:
            LOG.debug("Configure gobgp import Policy")
            start_time = time.time()

            target_state = self.setup_target_state(
                COMMON_NAME, self._import_route_targets
            )
            current_state = self.setup_current_state(COMMON_NAME)
            if target_state != current_state:
                self.need_reset_peers = True
            self.sync_objects(
                target_state=target_state,
                current_state=current_state,
                add_func=self.create_gobgp_object,
                del_func=self.del_gobgp_object,
            )
            self.update_peer()
            duration_metrics["update_policy_time"] = time.time() - start_time
            LOG.info(
                "Updating policy done for %0.4f sec",
                duration_metrics["update_policy_time"],
            )

        LOG.debug("Start getting announces from gobgp")
        start_time = time.time()
        (
            local_bgp_ce,
            local_bgp_vnet,
            remote_bgp_ce,
            remote_bgp_vnets,
            local_bgp_pr,
            remote_bgp_pr,
        ) = self.gobgp_client.get_paths(local_next_hop=self.source_ip)
        metrics["remote_ce_cnt"] = len(remote_bgp_ce)
        metrics["remote_cpr_cnt"] = len(remote_bgp_pr)
        duration_metrics["get_bgp_time"] = time.time() - start_time
        LOG.info(
            "Getting from gobgp done for %0.4f sec",
            duration_metrics["get_bgp_time"],
        )

        # Diff ce from files and from gobgp
        start_time = time.time()
        LOG.debug("Sync type 2 announces")
        created, deleted = self.sync_objects(
            target_state=local_ce,
            current_state=local_bgp_ce,
            add_func=self.gobgp_client.add_unicast_path,
            del_func=self.gobgp_client.del_unicast_path,
        )
        metrics["add_unicast_cnt"] = created
        metrics["del_unicast_cnt"] = deleted

        # Diff vnet from files and from gobgp
        LOG.debug("Sync type 3 announces")
        created, deleted = self.sync_objects(
            target_state=local_vnet,
            current_state=local_bgp_vnet,
            add_func=self.gobgp_client.add_multicast_path,
            del_func=self.gobgp_client.del_multicast_path,
        )
        metrics["add_multicast_cnt"] = created
        metrics["del_multicast_cnt"] = deleted

        # Diff client_prefixes from files and from gobgp
        LOG.debug("Sync type 5 announces")
        created, deleted = self.sync_objects(
            target_state=set(local_prefixes),
            current_state=local_bgp_pr,
            add_func=self.gobgp_client.add_prefix_path,
            del_func=self.gobgp_client.del_prefix_path,
        )
        duration_metrics["sync_bgp_time"] = time.time() - start_time
        metrics["add_prefix_cnt"] = created
        metrics["del_prefix_cnt"] = deleted
        LOG.info(
            "Sync announces done for %0.4f sec",
            duration_metrics["sync_bgp_time"],
        )

        uni_flows = set()
        bum_flows = set()
        start_time = time.time()
        LOG.debug("Prepare ovs flows")
        # Add flows for local l2 ports
        # TODO(aleks.popov): Add vrf support to Type 2
        for ce in local_ce:
            uni_flows = uni_flows.union(ce.to_flows(local=True))

        for vrf in self._vrfs:
            # Filter announces by RT in vrfs
            vrf.import_announces(local_prefixes, remote_bgp_pr)
            LOG.debug(
                "Convert %s announces to flow: local: %d, remote: %d",
                vrf,
                len(vrf.local_ce_prefixes),
                len(vrf.remote_ce_prefixes),
            )
            # Add flows from all vrf announces
            uni_flows = uni_flows.union(vrf.to_flows())

        if self.anycast_used:
            # Adding a flow so that anycast-checker can work for disabled
            # prefixes
            for prefix in disabled_anycast_prefixes:
                uni_flows = uni_flows.union(prefix.to_flows())

        # Group clients by VNI and add group flows for l2 ports
        # TODO(aleks.popov): Add vrf support to Type 3
        for vni in local_vni_nums:
            # Group of local l2 clients
            local_group = sorted(ce for ce in local_ce if ce.vni == vni)
            # Group of remote l2 clients (BUM only)
            remote_group = sorted(
                vnet for vnet in remote_bgp_vnets if vnet.vni == vni
            )
            LOG.debug(
                "Prepare BUM for VNI %d: " "local_group: %d, remote_group: %d",
                vni,
                len(local_group),
                len(remote_group),
            )

            # Prepare flows for BUM traffic
            bum_flows = bum_flows.union(
                evpnobj.OvsGroupActionFlows(
                    vni=vni,
                    local_group=local_group,
                    remote_group=remote_group,
                ).to_flows()
            )

            rem_ce_for_cur_vni = sorted(
                ce for ce in remote_bgp_ce if ce.vni == vni
            )
            # TODO(aleks.popov): May be optimize later
            if rem_ce_for_cur_vni:
                for rem_ce in rem_ce_for_cur_vni:
                    uni_flows = uni_flows.union(rem_ce.to_flows(local=False))
            else:
                if remote_group:
                    LOG.warning(
                        "VNI=%d: TYPE 2 announce was not found "
                        "(RFC violation), but TYPE 3 announce "
                        "exists, so we can use it to filter flow",
                        vni,
                    )
                    uni_flows = uni_flows.union(
                        set([vnet.to_filter_flow() for vnet in remote_group])
                    )
        # Add drop flows for dropped traffic counters
        uni_flows = uni_flows.union(evpnobj.generate_drop_flow())
        LOG.debug(
            "Generated %d unicast flows, %d broadcast flow",
            len(uni_flows),
            len(bum_flows),
        )
        metrics["ovs_flow_cnt"] = len(uni_flows) + len(bum_flows)
        duration_metrics["prep_ovs_time"] = time.time() - start_time
        LOG.info(
            "Prepare ovs flows done for %0.4f sec",
            duration_metrics["prep_ovs_time"],
        )

        start_time = time.time()
        LOG.debug("Sync flows in ovs")
        self.ovs_client.sync_flows(uni_flows.union(bum_flows))
        duration_metrics["sync_ovs_time"] = time.time() - start_time
        LOG.info(
            "Sync ovs flows done for %0.4f sec",
            duration_metrics["sync_ovs_time"],
        )

        # Send metrics
        for name, value in metrics.items():
            self._sender.send_counter(name, value)
        for name, value in duration_metrics.items():
            self._sender.send_duration(name, value)

    def _teardown(self):
        super(EvpnConnectorService, self)._teardown()
        # Call step final time to sync dataplane
        # to avoid possible race with removing CE while step is on
        self._step()
        LOG.info("Teardown is over")
