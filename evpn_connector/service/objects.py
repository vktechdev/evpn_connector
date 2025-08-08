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


import json
import logging

from evpn_connector.bgp.generated import gobgp_pb2
from evpn_connector.common import constants
from evpn_connector.ovs import common as ovs_cm


LOG = logging.getLogger(__name__)


class BaseObj(object):
    def __init__(self):
        super(BaseObj, self).__init__()

    def __hash__(self):
        return hash(id(self))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def from_dict(cls, obj_dict):
        return NotImplemented

    def to_dict(self):
        return NotImplemented

    @property
    def json(self):
        return json.dumps(self.to_dict())


class BaseVniObj(BaseObj):
    def __init__(self, vni, next_hop):
        super(BaseVniObj, self).__init__()
        self.vni = vni
        self.next_hop = next_hop
        self._validate_params()

    def _validate_params(self):
        if not (
            constants.MIN_VXLAN_VNI <= self.vni <= constants.MAX_VXLAN_VNI
        ):
            raise ValueError('Unsupported VNI value: "%s"' % self.vni)
        if not self.next_hop:
            raise ValueError('Unsupported NextHop value: "%s"' % self.next_hop)

    @property
    def rd_num(self):
        return self.vni

    @property
    def tun_id(self):
        return hex(self.vni)

    def __lt__(self, other):
        if isinstance(other, BaseVniObj):
            return (self.next_hop, self.vni) < (other.next_hop, other.vni)
        else:
            return NotImplemented


class BaseVniObjWithOfport(BaseVniObj):
    def __init__(self, vni, next_hop, ofport, port_type, tag):
        self._ofport = ofport
        self.port_type = port_type
        self.tag = tag
        super(BaseVniObjWithOfport, self).__init__(vni=vni, next_hop=next_hop)

    def __lt__(self, other):
        if isinstance(other, BaseVniObjWithOfport):
            return (self.tag, self.vni, self.next_hop, self._ofport) < (
                other.tag,
                other.vni,
                other.next_hop,
                other._ofport,
            )
        else:
            return NotImplemented

    def _validate_params(self):
        super(BaseVniObjWithOfport, self)._validate_params()

        if (
            self.port_type is not None
            and self.port_type not in constants.ALLOWED_CE_PORT_TYPES
        ):
            raise ValueError(
                'Allowed only %s types, but "%s"'
                % (constants.ALLOWED_CE_PORT_TYPES, self.port_type)
            )

    @property
    def ovs_encap_type(self):
        return self.port_type

    @property
    def ofport(self):
        ofport = self._ofport
        if (
            self.port_type == constants.EVPN_EDGE_TYPE_VXLAN
            and ofport == constants.UNKNOWN_OFPORT
        ):
            ofport = constants.VXLAN_PORT_OFPORT
        return ofport

    def _ovs_filter_match(
        self,
        table=constants.INPUT_FILTER_TABLE_NUM,
        prio=constants.NORMAL_PRIO,
        ofport=None,
    ):
        ofport = ofport or self.ofport
        res = "table=%d,priority=%d," % (table, prio)
        if self.port_type == constants.EVPN_EDGE_TYPE_VLAN:
            res += "in_port=%d,dl_vlan=%d" % (ofport, self.tag)
        elif self.port_type == constants.EVPN_EDGE_TYPE_VXLAN:
            # TODO(aleks.popov): May be add remote ip filter?
            res += "in_port=%d,tun_id=%d" % (ofport, self.vni)
        # Type: flat
        else:
            res += "in_port=%d" % ofport
        return res


class RouteTarget(BaseObj):
    def __init__(self, targets):
        super(RouteTarget, self).__init__()
        self.targets = set(targets)

    def __hash__(self):
        return hash(tuple([(asn, num) for asn, num in self.targets]))

    def __lt__(self, other):
        if isinstance(other, RouteTarget):
            return self.__hash__() < other.__hash__()
        else:
            return NotImplemented

    @classmethod
    def from_dict(cls, obj_dict, backup_key_name="exp_rt"):
        targets = obj_dict.get("rt")
        if targets is None:
            # Get export route target
            targets = obj_dict.get(backup_key_name, set())
        return cls(targets=targets)

    def to_dict(self):
        return self.targets

    def __str__(self):
        return "RT(%s)" % (
            ",".join(["%d:%d" % (asn, num) for asn, num in self.targets])
        )


class OvsFlow(BaseObj):
    def __init__(self, match, action):
        self._match = match
        self._action = action

    def to_string(self):
        return "%s %s" % (self._match, self._action)

    @property
    def action(self):
        return self._action

    @property
    def match(self):
        return self._match

    def __hash__(self):
        # Use only match for unique identify curent flow
        return hash(self._match)

    def __str__(self):
        return "Flow(match=%s %s)" % (self._match, self._action)

    def __lt__(self, other):
        if isinstance(other, OvsFlow):
            return self._match < other._match
        else:
            return NotImplemented


class OvsDropFlow(OvsFlow):
    def __init__(self, table):
        super(OvsDropFlow, self).__init__(
            match="table=%d,priority=%d"
            % (table, constants.LOWEST_ACTION_PRIO),
            action="actions=drop",
        )


class ClientEdge(BaseVniObjWithOfport):
    def __init__(
        self, mac, vni, ip, as_number, rt, ofport, port_type, tag, next_hop
    ):
        self.mac = mac
        self.ip = ip
        self.as_number = as_number
        self.rt = rt
        super(ClientEdge, self).__init__(
            vni=vni,
            next_hop=next_hop,
            ofport=ofport,
            port_type=port_type,
            tag=tag,
        )

    def _validate_params(self):
        super(ClientEdge, self)._validate_params()

        if not self.mac:
            raise ValueError('Unsupported MAC value: "%s"' % self.mac)

    @classmethod
    def from_dict(cls, obj_dict):
        return cls(
            mac=str(obj_dict.get("mac", "")),
            vni=int(obj_dict.get("vni", 0)),
            ip=str(obj_dict.get("ip", "")),
            as_number=int(obj_dict.get("rd_admin", 1)),
            next_hop=str(obj_dict.get("next_hop", "")),
            rt=RouteTarget.from_dict(obj_dict),
            ofport=int(obj_dict.get("ofport", constants.UNKNOWN_OFPORT)),
            port_type=obj_dict.get("type"),
            tag=int(obj_dict.get("tag", 0)),
        )

    def to_dict(self):
        return {
            "mac": self.mac,
            "vni": self.vni,
            "ip": self.ip,
            "rt": self.rt.to_dict(),
            "ofport": self.ofport,
            "type": self.port_type,
            "tag": self.tag,
            "next_hop": self.next_hop,
        }

    def __str__(self):
        return "CE(mac:%s ip=%s vni:%d nh=%s rt=%s)" % (
            self.mac,
            self.ip,
            self.vni,
            self.next_hop,
            self.rt,
        )

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash((self.mac, self.ip, self.vni, self.rt))

    def _ovs_reg_match(self, local=False, table=constants.OUTPUT_TABLE_NUM):
        res = "table=%d,priority=%d," % (table, constants.NORMAL_PRIO)
        reg1_str = ""
        if not local:
            # Send to vxlan only local traffic
            reg1_str = "reg1=%d," % constants.REG_FROM_LOCAL
        res += "reg0=%d,%sdl_dst=%s" % (self.vni, reg1_str, self.mac)
        return res

    def _ovs_to_out_table_action(self, local=False):
        res = "action="
        if self.port_type == constants.EVPN_EDGE_TYPE_VLAN:
            res += "pop_vlan,"

        reg1_value = constants.REG_FROM_REMOTE
        if local:
            reg1_value = constants.REG_FROM_LOCAL

        res += "set_field:%d->reg0,set_field:%d->reg1,resubmit(,%d)" % (
            self.vni,
            reg1_value,
            constants.OUTPUT_TABLE_NUM,
        )

        return res

    def ovs_output(self, for_group=False):
        res = ""

        if self.port_type == constants.EVPN_EDGE_TYPE_VLAN:
            if not for_group:
                res += ovs_cm.push_vlan_action() + ","
            res += "set_field:%s->vlan_vid,output:%d" % (
                ovs_cm.vid_present(self.tag),
                self.ofport,
            )
        elif self.port_type == constants.EVPN_EDGE_TYPE_VXLAN:
            res += "set_field:%s->tun_id,set_field:%s->tun_dst,output:%d" % (
                self.tun_id,
                self.next_hop,
                self.ofport,
            )
        # Type: flat
        else:
            res += "output:%d" % self.ofport

        return res

    def to_flows(self, local=False):
        filter_flow = OvsFlow(
            match=self._ovs_filter_match(),
            action=self._ovs_to_out_table_action(local=local),
        )
        out_flow = OvsFlow(
            match=self._ovs_reg_match(local=local),
            action="action=%s" % self.ovs_output(),
        )
        return {filter_flow, out_flow}


class ClientEdgePrefix(BaseVniObjWithOfport):
    def __init__(
        self,
        mac,
        prefix,
        prefix_len,
        vni,
        as_number,
        rt,
        ofport,
        port_type,
        tag,
        next_hop,
        router_mac,
    ):
        self.prefix = prefix
        self.prefix_len = prefix_len
        self.mac = mac
        self.as_number = as_number
        self.rt = rt
        self.router_mac = router_mac
        super(ClientEdgePrefix, self).__init__(
            vni=vni,
            next_hop=next_hop,
            ofport=ofport,
            port_type=port_type,
            tag=tag,
        )

    @property
    def is_anycast_prefix(self):
        return False

    def _validate_params(self):
        super(ClientEdgePrefix, self)._validate_params()

        if not self.prefix:
            raise ValueError('Unsupported prefix value: "%s"' % self.prefix)

        if self.prefix_len is None or not 0 <= self.prefix_len <= 32:
            raise ValueError(
                'Unsupported prefix_len value: "%s"' % self.prefix_len
            )

    @classmethod
    def from_dict(cls, obj_dict):
        return cls(
            prefix=str(obj_dict.get("prefix", "")),
            prefix_len=int(obj_dict.get("prefix_len", "")),
            mac=str(obj_dict.get("mac", "")),
            router_mac=str(
                obj_dict.get(
                    "router_mac", constants.TYPE_5_DEFAULT_ROUTER_MAC_EXTENDED
                )
            ),
            vni=int(obj_dict.get("vni", 0)),
            as_number=int(obj_dict.get("rd_admin", 1)),
            next_hop=str(obj_dict.get("next_hop", "")),
            rt=RouteTarget.from_dict(obj_dict),
            ofport=int(obj_dict.get("ofport", constants.UNKNOWN_OFPORT)),
            port_type=obj_dict.get("type"),
            tag=int(obj_dict.get("tag", 0)),
        )

    def to_dict(self):
        return {
            "prefix": self.prefix,
            "prefix_len": self.prefix_len,
            "mac": self.mac,
            "router_mac": self.router_mac,
            "vni": self.vni,
            "rt": self.rt.to_dict(),
            "ofport": self.ofport,
            "type": self.port_type,
            "tag": self.tag,
            "next_hop": self.next_hop,
        }

    def __str__(self):
        return "CEP(prefix:%s/%s vni:%d nh=%s rt=%s)" % (
            self.prefix,
            self.prefix_len,
            self.vni,
            self.next_hop,
            self.rt,
        )

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash(
            (self.prefix, self.prefix_len, self.vni, self.rt, self.next_hop)
        )

    @property
    def _out_prio(self):
        return self.prefix_len + constants.NORMAL_PRIO

    def ecmp_group(self, vrf=None):
        if not vrf:
            vrf = self.vni
        return _ecmp_group_to_str(vrf, self.prefix, self.prefix_len)

    def _ovs_arp_proxy_match(self):
        high_prio = constants.NORMAL_PRIO + 1
        # Filter only arp requests
        return self._ovs_filter_match(prio=high_prio) + ",arp"

    def get_filter_flow(self, vrf, local=False):
        return OvsFlow(
            match=self._ovs_filter_match(),
            action=self._ovs_to_out_table_action(vrf=vrf, local=local),
        )

    def get_out_flow(self, vrf, local=False):
        return OvsFlow(
            match=self._ovs_reg_match(vrf=vrf, prio=self._out_prio),
            action="action=%s" % self.ovs_output(local=local),
        )

    @property
    def apr_proxy_flow(self):
        proxy_action = ovs_cm.get_arp_proxy_responder_action(
            mac=constants.ARP_PROXY_MAC
        )
        return OvsFlow(
            match=self._ovs_arp_proxy_match(),
            action="action=%s" % proxy_action,
        )

    def to_flows(self, local=False, vrf=None, add_filter=True):
        if vrf is None:
            vrf = self.vni
        flows = set((self.get_out_flow(vrf=vrf, local=local),))
        if add_filter:
            flows.add(self.get_filter_flow(vrf=vrf, local=local))
        if local:
            flows.add(self.apr_proxy_flow)
        return flows

    def _ovs_to_out_table_action(
        self, vrf, local=False, action_prefix="action="
    ):
        res = action_prefix
        if self.port_type == constants.EVPN_EDGE_TYPE_VLAN:
            res += "pop_vlan,"

        # Write VRF number to reg2
        res += "set_field:%d->reg2,resubmit(,%d)" % (
            vrf,
            constants.OUTPUT_TABLE_NUM,
        )
        return res

    def _ovs_reg_match(
        self, vrf, table=constants.OUTPUT_TABLE_NUM, prio=constants.NORMAL_PRIO
    ):
        # Allowed only ip traffic!
        return "table=%d,priority=%d,ip,reg2=%d,nw_dst=%s/%d" % (
            table,
            prio,
            vrf,
            self.prefix,
            self.prefix_len,
        )

    def ovs_output(self, local=False):
        res = ""
        if local:
            res = "dec_ttl,set_field:%s->eth_dst," % self.mac
        else:
            res = "dec_ttl,set_field:%s->eth_dst," % self.router_mac

        if self.port_type == constants.EVPN_EDGE_TYPE_VLAN:
            res += "set_field:%s->vlan_vid,output:%d" % (
                ovs_cm.vid_present(self.tag),
                self.ofport,
            )
        elif self.port_type == constants.EVPN_EDGE_TYPE_VXLAN:
            res += "set_field:%s->tun_id,set_field:%s->tun_dst,output:%d" % (
                self.tun_id,
                self.next_hop,
                self.ofport,
            )
        # Type: flat
        else:
            res += "output:%d" % self.ofport

        return res


class ClientEdgePrefixAnycast(ClientEdgePrefix):
    def __init__(
        self,
        mac,
        prefix,
        prefix_len,
        vni,
        as_number,
        rt,
        ofport,
        port_type,
        tag,
        next_hop,
        router_mac,
        anycast_check_ofport,
        anycast_check_mac,
        dst_ip,
        check_ip,
        internal_dst_ip,
        internal_checker_ip,
        conntrack_zone,
    ):
        self.anycast_check_ofport = anycast_check_ofport
        self.anycast_check_mac = anycast_check_mac
        self.dst_ip = dst_ip
        self.check_ip = check_ip
        self.internal_dst_ip = internal_dst_ip
        self.internal_checker_ip = internal_checker_ip
        self.conntrack_zone = conntrack_zone
        self.disabled = False
        super(ClientEdgePrefixAnycast, self).__init__(
            mac=mac,
            prefix=prefix,
            prefix_len=prefix_len,
            vni=vni,
            as_number=as_number,
            rt=rt,
            ofport=ofport,
            port_type=port_type,
            tag=tag,
            next_hop=next_hop,
            router_mac=router_mac,
        )

    @property
    def is_anycast_prefix(self):
        return True

    def _validate_params(self):
        super(ClientEdgePrefixAnycast, self)._validate_params()

        if self.prefix == self.dst_ip:
            raise ValueError(
                'Anycast ip "%s" must not be equal to dst ip "%s"'
                % self.anycast_ip,
                self.dst_ip,
            )

    @classmethod
    def from_dict(cls, obj_dict):
        return cls(
            prefix=str(obj_dict.get("prefix", "")),
            prefix_len=int(obj_dict.get("prefix_len", "")),
            mac=str(obj_dict.get("mac", "")),
            router_mac=str(
                obj_dict.get(
                    "router_mac", constants.TYPE_5_DEFAULT_ROUTER_MAC_EXTENDED
                )
            ),
            vni=int(obj_dict.get("vni", 0)),
            as_number=int(obj_dict.get("rd_admin", 1)),
            next_hop=str(obj_dict.get("next_hop", "")),
            rt=RouteTarget.from_dict(obj_dict),
            ofport=int(obj_dict.get("ofport", constants.UNKNOWN_OFPORT)),
            port_type=obj_dict.get("type"),
            tag=int(obj_dict.get("tag", 0)),
            anycast_check_ofport=int(
                obj_dict.get(
                    "anycast_check_ofport",
                    constants.UNKNOWN_OFPORT,
                )
            ),
            anycast_check_mac=str(
                obj_dict.get(
                    "anycast_check_mac",
                    constants.ANYCAST_CHECKS_DST_MAC,
                )
            ),
            dst_ip=str(obj_dict.get("dst_ip", "")),
            check_ip=str(obj_dict.get("check_ip", "")),
            internal_dst_ip=str(obj_dict.get("internal_dst_ip", "")),
            internal_checker_ip=str(obj_dict.get("internal_checker_ip", "")),
            conntrack_zone=int(obj_dict.get("conntrack_zone", 0)),
        )

    def to_dict(self):
        result_dict = super(ClientEdgePrefixAnycast, self).to_dict()
        anycast_params_dict = {
            "anycast_check_ofport": self.anycast_check_ofport,
            "anycast_check_mac": self.anycast_check_mac,
            "dst_ip": self.dst_ip,
            "check_ip": self.check_ip,
            "internal_dst_ip": self.internal_dst_ip,
            "internal_checker_ip": self.internal_checker_ip,
            "conntrack_zone": self.conntrack_zone,
        }
        result_dict.update(anycast_params_dict)
        return result_dict

    def __str__(self):
        return "CEPAny(prefix:%s/%s vni:%d nh=%s rt=%s dst=%s)" % (
            self.prefix,
            self.prefix_len,
            self.vni,
            self.next_hop,
            self.rt,
            self.dst_ip,
        )

    def __repr__(self):
        return self.__str__()

    def _ovs_arp_proxy_match(self):
        high_prio = constants.NORMAL_PRIO + 1
        # Create apr proxy only for anycast-checker
        # Arp proxy for dst_ip must be created in parent prefix
        return (
            self._ovs_filter_match(
                prio=high_prio, ofport=self.anycast_check_ofport
            )
            + ",arp"
        )

    def _anycast_stateless_nat_action(self, src, dst, ofport, dst_mac):
        nat = "set_field:%s->nw_src,set_field:%s->nw_dst" % (src, dst)
        return "action=%s,set_field:%s->eth_dst,output:%d" % (
            nat,
            dst_mac,
            ofport,
        )

    def _anycast_checker_inbound_filter(
        self,
        in_port,
        dst_ip,
        table=constants.INPUT_FILTER_TABLE_NUM,
        prio=None,
    ):
        if not prio:
            cur_prio = constants.NORMAL_PRIO + 1
        else:
            cur_prio = prio
        return "table=%d,priority=%d,ip,in_port=%d,ip,nw_dst=%s" % (
            table,
            cur_prio,
            in_port,
            dst_ip,
        )

    def anycast_checker_flows(self):
        return {
            # Arp proxy for anycast-checker
            self.apr_proxy_flow,
            # Traffic from anycast-checker to client
            # Example:
            # table=0,priority=10,in_port=10000,ip,nw_dst=172.12.0.2
            # action=set_field:10.0.0.100->nw_src,set_field:10.0.0.1->nw_dst,
            # mod_dl_dst:36:e7:a5:7e:01:01,output:1001
            OvsFlow(
                match=self._anycast_checker_inbound_filter(
                    in_port=self.anycast_check_ofport,
                    dst_ip=self.internal_dst_ip,
                ),
                action=self._anycast_stateless_nat_action(
                    src=self.check_ip,
                    dst=self.dst_ip,
                    ofport=self.ofport,
                    dst_mac=self.mac,
                ),
            ),
            # Traffic from client to anycast-checker
            # Example:
            # table=0,priority=11,in_port=1001,ip,nw_dst=10.0.0.100
            # action=set_field:172.12.0.2->nw_src,set_field:172.12.0.1->nw_dst,
            # mod_dl_dst:36:e7:a5:7e:11:10,output:10000
            OvsFlow(
                match=self._anycast_checker_inbound_filter(
                    in_port=self.ofport,
                    dst_ip=self.check_ip,
                ),
                action=self._anycast_stateless_nat_action(
                    src=self.internal_dst_ip,
                    dst=self.internal_checker_ip,
                    ofport=self.anycast_check_ofport,
                    dst_mac=self.anycast_check_mac,
                ),
            ),
        }

    def get_filter_flow(self, vrf, local=False):
        high_prio = constants.NORMAL_PRIO + 1
        table = constants.INPUT_FILTER_TABLE_NUM
        fmatch = self._ovs_filter_match(prio=high_prio, table=table)
        fmatch += ",ip,nw_src=%s" % self.dst_ip
        out_action = "action=ct(commit,zone=%d,nat),%s" % (
            self.conntrack_zone,
            self._ovs_to_out_table_action(
                vrf=vrf,
                local=local,
                action_prefix="",
            ),
        )
        return {
            # Send not tracked packet to conntrack
            # Example:
            # table=0,priority=11,in_port=1001,ip,nw_src=10.0.0.1,ct_state=-trk
            # action=ct(table=0,zone=2)
            OvsFlow(
                match=self.add_ct_state_to_match(fmatch, trk="-trk"),
                action=self._to_ct_action(table),
            ),
            # Reverse NAT to anycast address. Only for established connections
            # Example:
            # table=0,priority=11,in_port=1001,ip,
            # nw_src=10.0.0.1,ct_state=+est+trk
            # action=ct(commit,zone=2,nat),set_field:100->reg2,resubmit(,1)
            OvsFlow(
                match=self.add_ct_state_to_match(fmatch, trk="+est+trk"),
                action=out_action,
            ),
        }

    def to_flows(self, local=False, vrf=None, add_filter=True, out_table=None):
        flows = self.anycast_checker_flows()
        if self.disabled:
            # If the anycast-checker check returns the client(dst_ip) is
            # unavailable, then we add a flow only for the anycast-checker to
            # work
            return flows

        if vrf is None:
            vrf = self.vni

        flows = flows.union(
            self.get_out_flow(vrf=vrf, local=local, table=out_table)
        )

        if add_filter:
            flows = flows.union(self.get_filter_flow(vrf=vrf, local=local))

        return flows

    def _to_ct_action(self, table):
        return "action=ct(table=%d,zone=%d)" % (table, self.conntrack_zone)

    def add_ct_state_to_match(self, match, trk):
        return match + ",ct_state=%s" % trk

    def _ct_nat_action(self, dst):
        return "ct(commit,zone=%d,nat(dst=%s))" % (self.conntrack_zone, dst)

    def get_out_flow_no_trk(self, vrf, local=False, table=None):
        table = table or constants.OUTPUT_TABLE_NUM
        # Send not tracked packet to conntrack
        # Example:
        # table=1,priority=42,ip,reg2=100,nw_dst=10.0.0.10/32,ct_state=-trk
        # action=ct(table=2,zone=2)
        return OvsFlow(
            match=self.add_ct_state_to_match(
                self._ovs_reg_match(vrf=vrf, prio=self._out_prio),
                trk="-trk",
            ),
            action=self._to_ct_action(table),
        )

    def get_out_flow_trk(self, vrf, local=False, table=None):
        table = table or constants.OUTPUT_TABLE_NUM
        # Send tracked packet to nat
        # Example:
        # table=1,priority=42,ip,reg2=100,nw_dst=10.0.0.10/32,ct_state=+trk
        # action=ct(commit,zone=2,nat(dst=10.0.0.1)),dec_ttl,
        # mod_dl_dst:36:e7:a5:7e:01:01,output:1001
        return OvsFlow(
            match=self.add_ct_state_to_match(
                self._ovs_reg_match(vrf=vrf, prio=self._out_prio),
                trk="+trk",
            ),
            action="action=%s,%s"
            % (
                self._ct_nat_action(dst=self.dst_ip),
                self.ovs_output(local=local),
            ),
        )

    def get_out_flow(self, vrf, local=False, table=None):
        table = table or constants.OUTPUT_TABLE_NUM
        return {
            self.get_out_flow_no_trk(vrf=vrf, local=local, table=table),
            self.get_out_flow_trk(vrf=vrf, local=local, table=table),
        }


class CEPrefixECMP(object):
    def __init__(
        self, vni, prefix, prefix_len, local_ce_prefixes, remote_ce_prefixes
    ):
        self.vni = vni
        self.prefix = prefix
        self.prefix_len = prefix_len
        self.local_ce_prefixes = local_ce_prefixes
        self.remote_ce_prefixes = remote_ce_prefixes

    @property
    def ecmp_group(self):
        return _ecmp_group_to_str(self.vni, self.prefix, self.prefix_len)

    @property
    def dst_count(self):
        return len(self.local_ce_prefixes) + len(self.remote_ce_prefixes)

    @property
    def _out_prio(self):
        return self.prefix_len + constants.NORMAL_PRIO

    def _ovs_multipath_match(
        self, vrf, table=constants.OUTPUT_TABLE_NUM, prio=constants.NORMAL_PRIO
    ):
        # Allowed only ip traffic!
        return "table=%d,priority=%d,ip,reg2=%d,nw_dst=%s/%d" % (
            table,
            prio,
            vrf,
            self.prefix,
            self.prefix_len,
        )

    @property
    def _ovs_multipath_action(self, dst_table=constants.ECMP_TABLE_NUM):
        # See man 7 ovs-actions for multipath params
        # Write the remainder from the division of the hash into reg3
        multipath_action = "multipath(%s, 0, modulo_n, %d, 0, reg3[])" % (
            constants.ECMP_HASH_ALGORITHM,
            self.dst_count,
        )
        return "%s,resubmit(,%d)" % (multipath_action, dst_table)

    def _multipath_out_matches(
        self,
        vrf,
        modulus_num,
        table=constants.ECMP_TABLE_NUM,
        prio=constants.NORMAL_PRIO,
    ):
        # reg3 - multipath modulus number (remainder of hash division)
        return "table=%d,priority=%d,ip,reg2=%d,reg3=%d,nw_dst=%s/%d" % (
            table,
            prio,
            vrf,
            modulus_num,
            self.prefix,
            self.prefix_len,
        )

    def _ovs_ce_flows(
        self, vrf, ce_prefix, modulus_num, local=False, add_filter=True
    ):
        if ce_prefix.is_anycast_prefix:
            res = {
                OvsFlow(
                    match=ce_prefix.add_ct_state_to_match(
                        match=self._multipath_out_matches(
                            vrf=vrf,
                            modulus_num=modulus_num,
                            prio=self._out_prio,
                        ),
                        trk="-trk",
                    ),
                    action=ce_prefix.get_out_flow_no_trk(
                        vrf=vrf,
                        local=local,
                        table=constants.ECMP_TABLE_NUM,
                    ).action,
                ),
                OvsFlow(
                    match=ce_prefix.add_ct_state_to_match(
                        match=self._multipath_out_matches(
                            vrf=vrf,
                            modulus_num=modulus_num,
                            prio=self._out_prio,
                        ),
                        trk="+trk",
                    ),
                    action=ce_prefix.get_out_flow_trk(
                        vrf=vrf,
                        local=local,
                        table=constants.ECMP_TABLE_NUM,
                    ).action,
                ),
            }
            if add_filter:
                res = res.union(
                    ce_prefix.get_filter_flow(vrf=vrf, local=local)
                )
            if local:
                res = res.union(ce_prefix.anycast_checker_flows())
        else:
            res = set(
                (
                    OvsFlow(
                        match=self._multipath_out_matches(
                            vrf=vrf,
                            modulus_num=modulus_num,
                            prio=self._out_prio,
                        ),
                        action=ce_prefix.get_out_flow(
                            vrf=vrf, local=local
                        ).action,
                    ),
                )
            )
            if add_filter:
                res.add(ce_prefix.get_filter_flow(vrf=vrf, local=local))
            if local:
                res.add(ce_prefix.apr_proxy_flow)
        return res

    def to_flows(self, vrf=None, add_filter_for_remote=False):
        if vrf is None:
            vrf = self.vni

        flows = set()

        # Multipath flow
        flows.add(
            OvsFlow(
                match=self._ovs_multipath_match(vrf=vrf, prio=self._out_prio),
                action="action=%s" % self._ovs_multipath_action,
            )
        )

        modulus_num = 0
        for l_prefix in self.local_ce_prefixes:
            flows = flows.union(
                self._ovs_ce_flows(
                    vrf=vrf,
                    ce_prefix=l_prefix,
                    modulus_num=modulus_num,
                    local=True,
                )
            )
            modulus_num += 1
        for r_prefix in self.remote_ce_prefixes:
            flows = flows.union(
                self._ovs_ce_flows(
                    vrf=vrf,
                    ce_prefix=r_prefix,
                    modulus_num=modulus_num,
                    add_filter=add_filter_for_remote,
                )
            )
            modulus_num += 1

        return flows


class VRF(BaseObj):
    def __init__(self, vni, import_rt):
        super(VRF, self).__init__()
        self.vni = vni
        self.import_rt = import_rt

        self.local_ce_prefixes = []
        self.remote_ce_prefixes = []
        self.ecmp_vni_prefixes = set()
        self.ecmps = []

    @property
    def vrf_number(self):
        return self.vni

    def __hash__(self):
        return self.vni

    def __lt__(self, other):
        if isinstance(other, VRF):
            return self.targets < other.targets
        else:
            return NotImplemented

    @classmethod
    def from_dict(cls, obj_dict):
        return cls(
            vni=int(obj_dict.get("vni")),
            import_rt=RouteTarget.from_dict(
                obj_dict, backup_key_name="imp_rt"
            ),
        )

    def __str__(self):
        return "VRF-%d(import_rt:%s)" % (self.vni, self.import_rt)

    def to_dict(self):
        return {
            "vni": self.vni,
            "rt": self.rt.to_dict(),
        }

    def import_announces(self, local_ce_prefixes, remote_ce_prefixes):
        self.local_ce_prefixes = []
        self.remote_ce_prefixes = []

        for l_prefix in local_ce_prefixes:
            if self.vni == l_prefix.vni:
                LOG.debug("Add %s to %s by VNI match", l_prefix, self)
                self.local_ce_prefixes.append(l_prefix)

        for r_prefix in remote_ce_prefixes:
            if self.import_rt.targets.intersection(r_prefix.rt.targets):
                LOG.debug("Add %s to %s by RT match", r_prefix, self)
                self.remote_ce_prefixes.append(r_prefix)

        self.ecmp_vni_prefixes, self.ecmps = ecmp_from_prefixes(
            self.local_ce_prefixes, self.remote_ce_prefixes, self.vrf_number
        )

    @property
    def _ovs_to_out_table_action(self):
        return "action=set_field:%d->reg2,resubmit(,%d)" % (
            self.vrf_number,
            constants.OUTPUT_TABLE_NUM,
        )

    def _ovs_filter_match(
        self,
        table=constants.INPUT_FILTER_TABLE_NUM,
        prio=constants.NORMAL_PRIO,
    ):
        return "table=%d,priority=%d,in_port=%d,tun_id=%d" % (
            table,
            prio,
            constants.VXLAN_PORT_OFPORT,
            self.vrf_number,
        )

    @property
    def vrf_filter_flow_for_remote(self):
        return OvsFlow(
            match=self._ovs_filter_match(),
            action=self._ovs_to_out_table_action,
        )

    def to_flows(self):
        # Not create filter flow in table=0 for empty VRF
        if not self.local_ce_prefixes:
            return set()

        # Add common filter flow for all remote announces in current vrf
        flows = set((self.vrf_filter_flow_for_remote,))

        for ecmp in self.ecmps:
            flows = flows.union(ecmp.to_flows(vrf=self.vrf_number))

        for l_prefix in self.local_ce_prefixes:
            egroup = l_prefix.ecmp_group(vrf=self.vrf_number)
            if egroup not in self.ecmp_vni_prefixes:
                flows = flows.union(
                    l_prefix.to_flows(vrf=self.vrf_number, local=True)
                )

        for r_prefix in self.remote_ce_prefixes:
            egroup = r_prefix.ecmp_group(vrf=self.vrf_number)
            if egroup not in self.ecmp_vni_prefixes:
                flows = flows.union(
                    r_prefix.to_flows(vrf=self.vrf_number, add_filter=False)
                )

        return flows


class VirtNet(BaseVniObj):
    def __init__(self, vni, rt, next_hop, as_number):
        super(VirtNet, self).__init__(vni=vni, next_hop=next_hop)
        self.rt = rt
        self.as_number = as_number

    def __hash__(self):
        return hash((self.vni, self.next_hop, self.rt))

    @property
    def ovs_encap_type(self):
        # VirtNet used only in group rules for forward traffic to remote hosts
        return constants.EVPN_EDGE_TYPE_VXLAN

    @classmethod
    def from_dict(cls, obj_dict):
        return cls(
            vni=obj_dict.get("vni", 0),
            rt=RouteTarget.from_dict(obj_dict),
            next_hop=obj_dict.get("next_hop", ""),
            as_number=obj_dict.get("rd_admin", 1),
        )

    def _ovs_filter_match(
        self,
        table=constants.INPUT_FILTER_TABLE_NUM,
        ofport=constants.VXLAN_PORT_OFPORT,
    ):
        res = "table=%d,priority=%d,in_port=%d,tun_id=%d" % (
            table,
            constants.NORMAL_PRIO,
            ofport,
            self.vni,
        )
        return res

    def _ovs_to_out_table_action(self, local=False):
        res = "action="

        reg1_value = constants.REG_FROM_REMOTE
        if local:
            reg1_value = constants.REG_FROM_LOCAL

        res += "set_field:%d->reg0,set_field:%d->reg1,resubmit(,%d)" % (
            self.vni,
            reg1_value,
            constants.OUTPUT_TABLE_NUM,
        )

        return res

    def ovs_output(
        self, for_group=False, tun_ofport=constants.VXLAN_PORT_OFPORT
    ):
        return "set_field:%s->tun_id,set_field:%s->tun_dst,output:%d" % (
            self.tun_id,
            self.next_hop,
            tun_ofport,
        )

    def __str__(self):
        return "VN(vni=%d nh=%s rt=%s)" % (
            self.vni,
            self.next_hop,
            str(self.rt),
        )

    def to_dict(self):
        return {
            "vni": self.vni,
            "rt": self.rt.to_dict(),
            "next_hop": self.next_hop,
        }

    def to_filter_flow(self, local=False):
        filter_flow = OvsFlow(
            match=self._ovs_filter_match(),
            action=self._ovs_to_out_table_action(local=local),
        )
        return filter_flow


class OvsGroupActionFlows(object):
    def __init__(self, vni, local_group, remote_group):
        self.vni = vni
        self.local_group = local_group
        self.remote_group = remote_group

    def _match(self, reg1_value):
        return "table=%d,priority=%d,reg0=%d,reg1=%d" % (
            constants.OUTPUT_TABLE_NUM,
            constants.LOW_PRIO,
            self.vni,
            reg1_value,
        )

    @staticmethod
    def _actions(groups):
        flat_out = [
            port.ovs_output(for_group=True)
            for port in groups
            if port.ovs_encap_type == constants.EVPN_EDGE_TYPE_FLAT
        ]
        vxlan_out = [
            port.ovs_output(for_group=True)
            for port in groups
            if port.ovs_encap_type == constants.EVPN_EDGE_TYPE_VXLAN
        ]
        vlan_out = [
            port.ovs_output(for_group=True)
            for port in groups
            if port.ovs_encap_type == constants.EVPN_EDGE_TYPE_VLAN
        ]
        # To correctly build a set of actions, you need to work on the packets
        # in the correct order. For example, if the vlan header is set in the
        # middle of a set of actions, then this header will be set for all
        # further outputs. Therefore, you need to do such changing actions once
        # for a group of output actions. So we output the flat packets first.
        # The next packets with a vxlan header in the port for vxlan. Lastly,
        # we output packets to the vlan, preceded by setting the vlan header
        actions = flat_out + vxlan_out
        if vlan_out:
            actions += [ovs_cm.push_vlan_action()] + vlan_out
        return "actions=%s" % ",".join(actions)

    def to_flows(self):
        groups = self.local_group
        # Flow for BUM traffic from Remote+Local to Local ports
        rem_loc_flow = OvsFlow(
            match=self._match(constants.REG_FROM_REMOTE),
            action=self._actions(groups=groups),
        )
        if self.remote_group:
            groups = self.local_group + self.remote_group
        # Flow for BUM traffic from Local to Remote ports
        loc_rem_flow = OvsFlow(
            match=self._match(constants.REG_FROM_LOCAL),
            action=self._actions(groups=groups),
        )
        return {rem_loc_flow, loc_rem_flow}


class BaseGobgpObject(BaseObj):
    __priority__ = 100

    def __init__(self):
        super(BaseGobgpObject, self).__init__()

    def __lt__(self, other):
        if isinstance(other, BaseGobgpObject):
            return self.__priority__ < other.__priority__
        else:
            return NotImplemented

    def __hash__(self):
        return NotImplemented

    def from_grpc(self, grpc_object):
        raise NotImplementedError

    def to_grpc(self):
        raise NotImplementedError


class DefinedSet(BaseGobgpObject):
    __priority__ = 0

    def __init__(self, defined_type, name, defined_set_list):
        self.defined_type = defined_type
        self.name = name
        self.defined_set_list = tuple(sorted(defined_set_list))

    def __hash__(self):
        return hash((self.defined_type, self.name, self.defined_set_list))

    @classmethod
    def from_grpc(cls, grpc_defined_set):
        return cls(
            grpc_defined_set.defined_type,
            grpc_defined_set.name,
            grpc_defined_set.list,
        )

    def to_grpc(self):
        return gobgp_pb2.DefinedSet(
            defined_type=self.defined_type,
            name=self.name,
            list=self.defined_set_list,
        )


class Actions(BaseGobgpObject):
    def __init__(self, route_action=1):
        self.route_action = route_action

    def __hash__(self):
        return hash(self.route_action)

    @classmethod
    def from_grpc(cls, grpc_actions):
        return cls(grpc_actions.route_action)

    def to_grpc(self):
        return gobgp_pb2.Actions(route_action=self.route_action)


class MatchSet(BaseGobgpObject):
    def __init__(self, type, defined_set_name):
        self.type = type
        self.defined_set_name = defined_set_name

    def __hash__(self):
        return hash((self.type, self.defined_set_name))

    @classmethod
    def from_grpc(cls, grpc_match_set):
        return cls(grpc_match_set.type, grpc_match_set.name)

    def to_grpc(self):
        return gobgp_pb2.MatchSet(
            type=self.type,
            name=self.defined_set_name,
        )


class Conditions(BaseGobgpObject):
    def __init__(self, ext_commm_match_set, rpki_result=-1):
        self.ext_community_set = ext_commm_match_set
        self.rpki_result = rpki_result

    def __hash__(self):
        return hash((self.ext_community_set, self.rpki_result))

    @classmethod
    def from_grpc(cls, grpc_conditions):
        return cls(
            MatchSet.from_grpc(grpc_conditions.ext_community_set),
            grpc_conditions.rpki_result,
        )

    def to_grpc(self):
        return gobgp_pb2.Conditions(
            ext_community_set=MatchSet.to_grpc(self.ext_community_set),
            rpki_result=self.rpki_result,
        )


class Statement(BaseGobgpObject):
    __priority__ = 1

    def __init__(self, name, conditions, actions):
        self.name = name
        self.conditions = conditions
        self.actions = actions

    def __hash__(self):
        return hash((self.name, self.conditions, self.actions))

    @classmethod
    def from_grpc(cls, grpc_statement):
        return cls(
            grpc_statement.name,
            Conditions.from_grpc(grpc_statement.conditions),
            Actions.from_grpc(grpc_statement.actions),
        )

    def to_grpc(self):
        return gobgp_pb2.Statement(
            name=self.name,
            conditions=Conditions.to_grpc(self.conditions),
            actions=Actions.to_grpc(self.actions),
        )


class Policy(BaseGobgpObject):
    __priority__ = 2

    def __init__(self, name, statements):
        self.name = name
        self.statements = tuple(sorted(statements))

    def __hash__(self):
        return hash((self.name, self.statements))

    @classmethod
    def from_grpc(cls, grpc_policy):
        return cls(
            grpc_policy.name,
            [Statement.from_grpc(s) for s in grpc_policy.statements],
        )

    def to_grpc(self):
        return gobgp_pb2.Policy(
            name=self.name,
            statements=[Statement.to_grpc(s) for s in self.statements],
        )


class PolicyAssignment(BaseGobgpObject):
    __priority__ = 3

    def __init__(self, name, direction, policies, default_action):
        self.name = name
        self.direction = direction
        self.policies = tuple(sorted(policies))
        self.default_action = default_action

    def __hash__(self):
        return hash(
            (self.name, self.direction, self.policies, self.default_action)
        )

    @classmethod
    def from_grpc(cls, grpc_assignment):
        return cls(
            grpc_assignment.name,
            grpc_assignment.direction,
            [Policy.from_grpc(p) for p in grpc_assignment.policies],
            grpc_assignment.default_action,
        )

    def to_grpc(self):
        return gobgp_pb2.PolicyAssignment(
            name=self.name,
            direction=self.direction,
            policies=[Policy.to_grpc(p) for p in self.policies],
            default_action=self.default_action,
        )


def vnet_from_ce(ce_list):
    vnets = {}
    for edge in ce_list:
        if edge.vni not in vnets:
            vnets[edge.vni] = VirtNet(
                vni=edge.vni,
                rt=edge.rt,
                next_hop=edge.next_hop,
                as_number=edge.as_number,
            )
        else:
            if vnets[edge.vni].rt != edge.rt:
                # For now let's just make a warning
                LOG.warning(
                    "Found client with equal vni, but different "
                    "route target: vni=%d rt=%s",
                    edge.vni,
                    str(edge.rt),
                )
    LOG.debug("Parsed %d virt nets from client configs", len(vnets))
    return set(vnets.keys()), set(vnets.values())


def ecmp_from_prefixes(local_ce_prefixes, remote_ce_prefixes, vrf):
    grouped_pr = {}
    for l_prefix in local_ce_prefixes:
        if l_prefix.ecmp_group(vrf) not in grouped_pr:
            grouped_pr[l_prefix.ecmp_group(vrf)] = {
                "local": [],
                "remote": [],
            }
        grouped_pr[l_prefix.ecmp_group(vrf)]["local"].append(l_prefix)

    for r_prefix in remote_ce_prefixes:
        if r_prefix.ecmp_group(vrf) not in grouped_pr:
            grouped_pr[r_prefix.ecmp_group(vrf)] = {
                "local": [],
                "remote": [],
            }
        grouped_pr[r_prefix.ecmp_group(vrf)]["remote"].append(r_prefix)

    ecmp_vni_prefixes = set()
    ecmps = []
    for ecmp_group, prefixes in grouped_pr.items():
        if (len(prefixes["local"]) + len(prefixes["remote"])) > 1:
            LOG.debug("Found ECMP prefix %s", ecmp_group)
            vrf, prefix, prefix_len = _str_to_ecmp_group(ecmp_group)
            ecmps.append(
                CEPrefixECMP(
                    vrf,
                    prefix,
                    prefix_len,
                    prefixes["local"],
                    prefixes["remote"],
                )
            )
            ecmp_vni_prefixes.add(ecmp_group)

    return ecmp_vni_prefixes, ecmps


def _ecmp_group_to_str(vrf, prefix, prefix_len):
    return "%d:%s/%d" % (vrf, prefix, prefix_len)


def _str_to_ecmp_group(prefix_str):
    vrf, prefix_mask = prefix_str.strip().split(":")
    prefix, prefix_len = prefix_mask.strip().split("/")
    return int(vrf), prefix, int(prefix_len)


def generate_drop_flow():
    drop_inp_table = OvsDropFlow(table=constants.INPUT_FILTER_TABLE_NUM)
    drop_out_table = OvsDropFlow(table=constants.OUTPUT_TABLE_NUM)
    drop_ecmp_table = OvsDropFlow(table=constants.ECMP_TABLE_NUM)
    return {drop_inp_table, drop_out_table, drop_ecmp_table}
