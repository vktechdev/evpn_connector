#!/usr/bin/env python
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
from __future__ import absolute_import
from __future__ import print_function

import logging
import netaddr
import time

from google.protobuf.any_pb2 import Any
import grpc

from evpn_connector.bgp.generated import attribute_pb2
from evpn_connector.bgp.generated import gobgp_pb2
from evpn_connector.bgp.generated import gobgp_pb2_grpc
from evpn_connector.common import constants
from evpn_connector.service import objects as evpnobj

LOG = logging.getLogger(__name__)
BGP_ORIGIN = 2
EXT_COM_RT_SUBTYPE = 2
VXLAN_ENCAP_TYPE = 8
PMSI_TYPE_INGRESS_REPLICATION = 6
TYPE_5_GW_ADDRESS = "0.0.0.0"
PROTOBUF_NIL = "<nil>"
MPREACHNLRI_TYPE_NAME = "type.googleapis.com/apipb.MpReachNLRIAttribute"
EXTC_TYPE_NAME = "type.googleapis.com/apipb.ExtendedCommunitiesAttribute"
TOSE_TYPE_NAME = "type.googleapis.com/apipb.TwoOctetAsSpecificExtended"
PMSI_TYPE_NAME = "type.googleapis.com/apipb.PmsiTunnelAttribute"
ROUTER_MAC_EXT_TYPE_NAME = "type.googleapis.com/apipb.RouterMacExtended"

STUB = None

"""
# install golang>1.11, protoc (brew install protobuf), protoc-gen-go

$ pip install grpcio-tools
$ git clone git://github.com/osrg/gobgp
$ cd gobgp

change api/*.proto:
```
diff --git a/api/attribute.proto b/api/attribute.proto
index 4cf844f..7bf9452 100644
--- a/api/attribute.proto
+++ b/api/attribute.proto
@@ -21,7 +21,7 @@

 syntax = "proto3";

-import "any/any.proto";
+import "google/protobuf/any.proto";
 import "gobgp.proto";

 package gobgpapi;
diff --git a/api/gobgp.proto b/api/gobgp.proto
index b61b475..52dd9da 100644
--- a/api/gobgp.proto
+++ b/api/gobgp.proto
@@ -21,9 +21,9 @@

 syntax = "proto3";

-import "any/any.proto";
-import "empty/empty.proto";
-import "timestamp/timestamp.proto";
+import "google/protobuf/any.proto";
+import "google/protobuf/empty.proto";
+import "google/protobuf/timestamp.proto";

 package gobgpapi;


```

$ mkdir ./py_out
$ python -m grpc_tools.protoc -I./api --python_out=./py_out/ \
--grpc_python_out=./py_out/ \
api/gobgp.proto api/attribute.proto api/capability.proto

Voila, you've got everything you need in ./py_out !

grpc_tools generate absolute imports of generated files related to root,
so maybe you need to replace them with
tools/replace-protobuf-local-imports.sh path/to/generated/files
"""


def unpack_protobuf_message(struct, module=attribute_pb2):
    """Unpacks message with `Any` type.

    After that you can use returned structure like common python's
    object. Searches type of needed message in specified module than
    unpacks bytes of specified structure to this defined message.

    Args:
        struct(google.protobuf.any_pb2.Any): structure which we want
            to unpack
        module: generated python's module with definitions of protobuf
            messages

    Returns:
        gobgp_pb2.<SomeClassOfMessage>

    """
    if type(struct) != Any:
        raise TypeError("You should specify struct with type Any to unpack")

    message = getattr(module, struct.type_url.split(".")[-1])()
    struct.Unpack(message)

    return message


def _simplify_unicast_struct(struct):
    res = {}
    # Need for extract: mac, rd_admin, ip, next_hop, vni, rt_asn, rt_num
    # Convert protobuf message to dict

    nlri = unpack_protobuf_message(struct.paths[0].nlri)

    rd = unpack_protobuf_message(nlri.rd)

    res["mac"] = nlri.mac_address
    # Extract rd_admin only if it's AS_number. Needed only for local announces
    try:
        res["rd_admin"] = int(rd.admin)
    except ValueError:
        LOG.debug(
            "Get macadv announce with mac: %s and non-ASN RD: %s",
            nlri.mac_address,
            rd.admin,
        )
    res["ip"] = nlri.ip_address
    if res["ip"] == PROTOBUF_NIL:
        res["ip"] = ""
    # Get only first label from announce
    res["vni"] = nlri.labels[0]

    res["rt"] = []
    # All remote clients has type from EncapExtended attribute
    # Curently we support only VXLAN
    res["type"] = constants.EVPN_EDGE_TYPE_VXLAN

    pattrs = struct.paths[0].pattrs
    # Pattrs may be list with random order
    for pattr in pattrs:
        if pattr.type_url == MPREACHNLRI_TYPE_NAME:
            # TODO(aleks.popov): Add ecmp support
            pa = unpack_protobuf_message(pattr)

            res["next_hop"] = pa.next_hops[0]

        elif pattr.type_url == EXTC_TYPE_NAME:
            pa = unpack_protobuf_message(pattr)
            for community in pa.communities:
                if community.type_url == TOSE_TYPE_NAME:
                    comm = unpack_protobuf_message(community)

                    res["rt"].append((comm.asn, comm.local_admin))
    return evpnobj.ClientEdge.from_dict(res)


def _simplify_prefix_struct(struct):
    result = []
    for path in struct.paths:
        # Need for extract: prefix, rd_admin, next_hop, vni, rt_asn, rt_num

        nlri = unpack_protobuf_message(path.nlri)

        rd = unpack_protobuf_message(nlri.rd)

        res = {
            # For older protobuf version names in nlri may be ipPrefix and
            # ipPrefixLen
            "prefix": nlri.ip_prefix,
            "prefix_len": nlri.ip_prefix_len,
            "vni": nlri.label,
            "rt": [],
            # All remote clients has type from EncapExtended attribute Curently
            # we support only VXLAN
            "type": constants.EVPN_EDGE_TYPE_VXLAN,
        }

        # Extract rd_admin only if it's AS_number. Needed only for local
        # announces
        try:
            res["rd_admin"] = int(rd.admin)
        except ValueError:
            LOG.debug(
                "Get Prefix announce with ip/mask: %s/%s and non-ASN RD: %s",
                # FIXME: For older protobuf version names in nlri may be
                # ipPrefix and ipPrefixLen
                nlri.ip_prefix,
                nlri.ip_prefix_len,
                rd.admin,
            )

        pattrs = path.pattrs
        # Pattrs may be list with random order
        for pattr in pattrs:
            if pattr.type_url == MPREACHNLRI_TYPE_NAME:
                pa = unpack_protobuf_message(pattr)
                res["next_hop"] = pa.next_hops[0]
            elif pattr.type_url == EXTC_TYPE_NAME:
                pa = unpack_protobuf_message(pattr)
                for community in pa.communities:
                    if community.type_url == TOSE_TYPE_NAME:
                        comm = unpack_protobuf_message(community)
                        res["rt"].append((comm.asn, comm.local_admin))
                    if community.type_url == ROUTER_MAC_EXT_TYPE_NAME:
                        comm = unpack_protobuf_message(community)
                        res["router_mac"] = comm.mac

        if "router_mac" not in res:
            LOG.warning("Not found RouterMacExtended in announce. Use default")
            res["router_mac"] = constants.TYPE_5_DEFAULT_ROUTER_MAC_EXTENDED

        result.append(evpnobj.ClientEdgePrefix.from_dict(res))

    return result


def _simplify_multicast_struct(multicast_struct):
    # Convert protobuf message to dict

    res = {}
    # Need for extract: rd_admin, next_hop, vni, rt_asn, rt_num
    nlri = unpack_protobuf_message(multicast_struct.paths[0].nlri)
    rd = unpack_protobuf_message(nlri.rd)

    # Extract rd_admin only if it's AS_number. Needed only for local announces
    try:
        res["rd_admin"] = int(rd.admin)
    except ValueError:
        LOG.debug("Get multicast announce with non-ASN RD: %s", rd.admin)
    res["rt"] = []

    pattrs = multicast_struct.paths[0].pattrs
    # Pattrs may be list with random order
    for pattr in pattrs:
        if pattr.type_url == MPREACHNLRI_TYPE_NAME:
            # TODO(aleks.popov): Add ecmp support
            pa = unpack_protobuf_message(pattr)
            res["next_hop"] = pa.next_hops[0]
        elif pattr.type_url == EXTC_TYPE_NAME:
            pa = unpack_protobuf_message(pattr)
            for community in pa.communities:
                if community.type_url == TOSE_TYPE_NAME:
                    comm = unpack_protobuf_message(community)

                    res["rt"].append((comm.asn, comm.local_admin))
        elif pattr.type_url == PMSI_TYPE_NAME:
            pa = unpack_protobuf_message(pattr)
            res["vni"] = pa.label
    return evpnobj.VirtNet.from_dict(res)


class BGPClient(object):
    family = gobgp_pb2.Family(
        afi=gobgp_pb2.Family.AFI_L2VPN, safi=gobgp_pb2.Family.SAFI_EVPN
    )
    simplify_map = {
        constants.EVPN_MACADV_TYPE: _simplify_unicast_struct,
        constants.EVPN_MULTICAST_TYPE: _simplify_multicast_struct,
        constants.EVPN_PREFIX_TYPE: _simplify_prefix_struct,
    }

    def __init__(self, gobgp_channel, grpc_timeout_sec, router_mac_type5):
        self._router_mac_type5 = router_mac_type5
        self.gobgp_channel = gobgp_channel
        self.timeout_seconds = grpc_timeout_sec
        self.bgp_origin = Any()
        self.bgp_origin.Pack(attribute_pb2.OriginAttribute(origin=BGP_ORIGIN))

        global STUB
        if not STUB:
            # channel and stub are thread-safe
            channel = grpc.insecure_channel(self.gobgp_channel)
            STUB = gobgp_pb2_grpc.GobgpApiStub(channel)
        self.stub = STUB

    @staticmethod
    def _get_ext_comm(rt, tunnel_type=VXLAN_ENCAP_TYPE, router_mac=""):
        # BGP Extended communities
        # Route target
        tgts = []
        for asn, num in rt.targets:
            rt_dict = {
                "sub_type": EXT_COM_RT_SUBTYPE,
                "asn": asn,
                "local_admin": num,
                "is_transitive": True,
            }
            rt = Any()
            rt.Pack(attribute_pb2.TwoOctetAsSpecificExtended(**rt_dict))
            tgts.append(rt)
        # Encapsulation type
        encap = Any()
        encap.Pack(attribute_pb2.EncapExtended(tunnel_type=tunnel_type))

        rtr_mac = Any()
        if router_mac:
            rtr_mac.Pack(attribute_pb2.RouterMacExtended(mac=router_mac))

        ext_community = Any()
        if router_mac:
            ext_community.Pack(
                attribute_pb2.ExtendedCommunitiesAttribute(
                    communities=tgts + [encap] + [rtr_mac]
                )
            )
        else:
            ext_community.Pack(
                attribute_pb2.ExtendedCommunitiesAttribute(
                    communities=tgts + [encap]
                )
            )
        return ext_community

    @staticmethod
    def _get_rd(rd_asn, rd_num):
        rd_addr = Any()
        rd_addr.Pack(
            attribute_pb2.RouteDistinguisherTwoOctetASN(
                admin=rd_asn,
                assigned=rd_num,
            )
        )
        return rd_addr

    def prepare_unicast_path(self, edge):
        """Prepare evpn Type 2 route"""
        # Route information
        rd = self._get_rd(edge.as_number, edge.rd_num)
        nlri = Any()
        nlri.Pack(
            attribute_pb2.EVPNMACIPAdvertisementRoute(
                mac_address=edge.mac,
                ip_address=edge.ip,
                labels=[edge.vni],
                rd=rd,
                esi=attribute_pb2.EthernetSegmentIdentifier(),
            )
        )

        # Route params
        # BGP Extended communities
        ext_community = self._get_ext_comm(edge.rt)

        # NLRI
        mp_reach_nlri = Any()
        mp_reach_nlri.Pack(
            attribute_pb2.MpReachNLRIAttribute(
                family=self.family,
                next_hops=[edge.next_hop],
                nlris=[nlri],
            )
        )

        path = gobgp_pb2.Path(
            nlri=nlri,
            pattrs=[self.bgp_origin, ext_community, mp_reach_nlri],
            family=self.family,
        )
        return path

    def add_unicast_path(self, edge):
        path = self.prepare_unicast_path(edge)
        LOG.info("Add macadv announce: %s", edge)
        return self.stub.AddPath(
            gobgp_pb2.AddPathRequest(
                table_type=gobgp_pb2.GLOBAL,
                path=path,
            ),
            self.timeout_seconds,
        )

    def del_unicast_path(self, edge):
        path = self.prepare_unicast_path(edge)
        LOG.info("Del macadv announce: %s", edge)
        return self.stub.DeletePath(
            gobgp_pb2.DeletePathRequest(
                table_type=gobgp_pb2.GLOBAL,
                family=self.family,
                path=path,
            ),
            self.timeout_seconds,
        )

    def prepare_multicast_path(self, vnet):
        """Add evpn Type 3 route"""
        # Route information
        rd = self._get_rd(vnet.as_number, vnet.rd_num)
        nlri = Any()
        nlri.Pack(
            attribute_pb2.EVPNInclusiveMulticastEthernetTagRoute(
                ip_address=vnet.next_hop,
                rd=rd,
            )
        )

        pmsi_dict = {
            "type": PMSI_TYPE_INGRESS_REPLICATION,
            "label": vnet.vni,
            "id": netaddr.IPAddress(vnet.next_hop).packed,
        }
        pmsi = Any()
        pmsi.Pack(attribute_pb2.PmsiTunnelAttribute(**pmsi_dict))

        # Route params
        ext_community = self._get_ext_comm(vnet.rt)

        # NLRI
        mp_reach_nlri = Any()
        mp_reach_nlri.Pack(
            attribute_pb2.MpReachNLRIAttribute(
                family=self.family,
                next_hops=[vnet.next_hop],
                nlris=[nlri],
            )
        )

        path = gobgp_pb2.Path(
            nlri=nlri,
            pattrs=[self.bgp_origin, pmsi, ext_community, mp_reach_nlri],
            family=self.family,
        )
        return path

    def add_multicast_path(self, vnet):
        LOG.info("Add multicast announce: %s", vnet)
        path = self.prepare_multicast_path(vnet)
        return self.stub.AddPath(
            gobgp_pb2.AddPathRequest(
                table_type=gobgp_pb2.GLOBAL,
                path=path,
            ),
            self.timeout_seconds,
        )

    def del_multicast_path(self, vnet):
        LOG.info("Del multicast announce: %s", vnet)
        path = self.prepare_multicast_path(vnet)
        return self.stub.DeletePath(
            gobgp_pb2.DeletePathRequest(
                table_type=gobgp_pb2.GLOBAL,
                family=self.family,
                path=path,
            ),
            self.timeout_seconds,
        )

    def prepare_prefix_path(self, edge_prefix):
        """Prepare evpn Type 5 route"""
        # Route information
        rd = self._get_rd(edge_prefix.as_number, edge_prefix.rd_num)
        nlri = Any()
        nlri.Pack(
            attribute_pb2.EVPNIPPrefixRoute(
                # FIXME: For older protobuf version names in nlri may be
                # ipPrefix and ipPrefixLen and gwAddress
                ip_prefix=edge_prefix.prefix,
                ip_prefix_len=edge_prefix.prefix_len,
                gw_address=TYPE_5_GW_ADDRESS,
                label=edge_prefix.vni,
                rd=rd,
                esi=attribute_pb2.EthernetSegmentIdentifier(),
            )
        )

        # Route params
        # BGP Extended communities for Type 5 (with RouterMacExtended)
        ext_community = self._get_ext_comm(
            rt=edge_prefix.rt, router_mac=self._router_mac_type5
        )

        # NLRI
        mp_reach_nlri = Any()
        mp_reach_nlri.Pack(
            attribute_pb2.MpReachNLRIAttribute(
                family=self.family,
                next_hops=[edge_prefix.next_hop],
                nlris=[nlri],
            )
        )

        path = gobgp_pb2.Path(
            nlri=nlri,
            pattrs=[self.bgp_origin, ext_community, mp_reach_nlri],
            family=self.family,
        )

        return path

    def add_prefix_path(self, edge_prefix):
        path = self.prepare_prefix_path(edge_prefix)
        LOG.info("Add Prefix announce: %s", edge_prefix)
        return self.stub.AddPath(
            gobgp_pb2.AddPathRequest(
                table_type=gobgp_pb2.GLOBAL,
                path=path,
            ),
            self.timeout_seconds,
        )

    def del_prefix_path(self, edge_prefix):
        path = self.prepare_prefix_path(edge_prefix)
        LOG.info("Del Prefix announce: %s", edge_prefix)
        return self.stub.DeletePath(
            gobgp_pb2.DeletePathRequest(
                table_type=gobgp_pb2.GLOBAL,
                family=self.family,
                path=path,
            ),
            self.timeout_seconds,
        )

    @staticmethod
    def filter_local_announces(objs, local_next_hop):
        client_edges, virt_nets, client_prefixes = objs

        local_edges = set()
        remote_edges = set()
        for edge in client_edges:
            if edge.next_hop == local_next_hop:
                local_edges.add(edge)
            else:
                remote_edges.add(edge)

        local_virt_nets = set()
        remote_virt_nets = set()
        for vnet in virt_nets:
            if vnet.next_hop == local_next_hop:
                local_virt_nets.add(vnet)
            else:
                remote_virt_nets.add(vnet)

        local_client_prefixes = set()
        remote_client_prefixes = set()
        for cprefix in client_prefixes:
            if cprefix.next_hop == local_next_hop:
                local_client_prefixes.add(cprefix)
            else:
                remote_client_prefixes.add(cprefix)

        return (
            local_edges,
            local_virt_nets,
            remote_edges,
            remote_virt_nets,
            local_client_prefixes,
            remote_client_prefixes,
        )

    def get_paths(self, local_next_hop=None):
        return self.filter_local_announces(self._get_paths(), local_next_hop)

    def _get_paths_from_gobgp(self, prefix_type):
        start_time = time.time()
        req = self.stub.ListPath(
            gobgp_pb2.ListPathRequest(
                table_type=gobgp_pb2.GLOBAL,
                family=self.family,
                prefixes=[gobgp_pb2.TableLookupPrefix(prefix=prefix_type)],
            ),
            self.timeout_seconds,
        )
        LOG.debug(
            "Get data from gobgp for %s type: %0.6f sec",
            prefix_type,
            time.time() - start_time,
        )
        return req

    def _get_paths(self):
        """Get paths from GoBGP"""
        return (
            self._get_obj(constants.EVPN_MACADV_TYPE),
            self._get_obj(constants.EVPN_MULTICAST_TYPE),
            self._get_obj(constants.EVPN_PREFIX_TYPE),
        )

    def _get_obj(self, prefix_type):
        """Get paths from GoBGP"""
        res = []
        req = self._get_paths_from_gobgp(prefix_type=prefix_type)
        start_time = time.time()
        for line in req:
            simplify_func = self.simplify_map[prefix_type]
            func_res = simplify_func(line.destination)
            if type(func_res) is list:
                res += func_res
            else:
                res.append(func_res)
        LOG.debug(
            "Parse %d prefixes from gobgp for %s type: %0.6f sec",
            len(res),
            prefix_type,
            time.time() - start_time,
        )
        return res

    def _extract_response_from_grpc(self, grpc_channel):
        response = [item for item in grpc_channel]
        if len(response) > 0:
            return response
        return None

    def add_defined_set(self, defined_set):
        self.stub.AddDefinedSet(
            gobgp_pb2.AddDefinedSetRequest(
                defined_set=defined_set.to_grpc(),
            ),
            self.timeout_seconds,
        )
        LOG.debug("Defined set %s added to GoBGP", defined_set.name)

    def delete_defined_set(self, defined_set, full_deletion=False):
        self.stub.DeleteDefinedSet(
            gobgp_pb2.DeleteDefinedSetRequest(
                defined_set=defined_set.to_grpc(),
                all=full_deletion,
            ),
            self.timeout_seconds,
        )
        LOG.debug("Defined set %s removed from GoBGP", defined_set.name)

    def get_defined_set(self, defined_type, defined_set_name):
        defined_set_channel = self.stub.ListDefinedSet(
            gobgp_pb2.ListDefinedSetRequest(
                defined_type=defined_type,
                name=defined_set_name,
            ),
            self.timeout_seconds,
        )
        resp = self._extract_response_from_grpc(defined_set_channel)
        if resp is None:
            return None
        return evpnobj.DefinedSet.from_grpc(resp[0].defined_set)

    def add_statement(self, statement):
        self.stub.AddStatement(
            gobgp_pb2.AddStatementRequest(
                statement=statement.to_grpc(),
            ),
            self.timeout_seconds,
        )
        LOG.debug("Statement %s added to GoBGP", statement.name)

    def delete_statement(self, statement, full_deletion=False):
        self.stub.DeleteStatement(
            gobgp_pb2.DeleteStatementRequest(
                statement=statement.to_grpc(),
                all=full_deletion,
            ),
            self.timeout_seconds,
        )
        LOG.debug("Statement %s removed from GoBGP", statement.name)

    def get_statement(self, statement_name):
        statement_channel = self.stub.ListStatement(
            gobgp_pb2.ListStatementRequest(name=statement_name),
            self.timeout_seconds,
        )
        resp = self._extract_response_from_grpc(statement_channel)
        if resp is None:
            return None
        return evpnobj.Statement.from_grpc(resp[0].statement)

    def add_policy(self, policy):
        self.stub.AddPolicy(
            gobgp_pb2.AddPolicyRequest(
                policy=policy.to_grpc(),
                refer_existing_statements=True,
            ),
            self.timeout_seconds,
        )
        LOG.debug("Policy %s added to GoBGP", policy.name)

    def delete_policy(self, policy, full_deletion=False):
        self.stub.DeletePolicy(
            gobgp_pb2.DeletePolicyRequest(
                policy=policy.to_grpc(),
                preserve_statements=True,
                all=full_deletion,
            ),
            self.timeout_seconds,
        )
        LOG.debug("Policy %s removed from GoBGP", policy.name)

    def get_policy(self, policy_name):
        policy_channel = self.stub.ListPolicy(
            gobgp_pb2.ListPolicyRequest(
                name=policy_name,
            ),
            self.timeout_seconds,
        )
        resp = self._extract_response_from_grpc(policy_channel)
        if resp is None:
            return None
        return evpnobj.Policy.from_grpc(resp[0].policy)

    def add_policy_assignment(self, policy_assignment):
        self.stub.AddPolicyAssignment(
            gobgp_pb2.AddPolicyAssignmentRequest(
                assignment=policy_assignment.to_grpc(),
            ),
            self.timeout_seconds,
        )
        LOG.debug("Policy assignment %s add to GoBGP", policy_assignment.name)

    def delete_policy_assignment(self, policy_assignment, full_deletion=False):
        self.stub.DeletePolicyAssignment(
            gobgp_pb2.DeletePolicyAssignmentRequest(
                assignment=policy_assignment.to_grpc(),
                all=full_deletion,
            ),
            self.timeout_seconds,
        )
        LOG.debug(
            "Policy assignment %s removed from GoBGP", policy_assignment.name
        )

    def get_policy_assignment(self, pa_name, pa_direction):
        policy_assignment_channel = self.stub.ListPolicyAssignment(
            gobgp_pb2.ListPolicyAssignmentRequest(
                name=pa_name,
                direction=pa_direction,
            ),
            self.timeout_seconds,
        )
        resp = self._extract_response_from_grpc(policy_assignment_channel)
        if resp is None or len(resp[0].assignment.policies) == 0:
            return None
        return evpnobj.PolicyAssignment.from_grpc(resp[0].assignment)

    def list_peer(self, peer_address):
        list_peers_channel = self.stub.ListPeer(
            gobgp_pb2.ListPeerRequest(
                address=peer_address,
            ),
            self.timeout_seconds,
        )
        resp = self._extract_response_from_grpc(list_peers_channel)
        return resp

    def reset_peer(self, address, soft, direction):
        self.stub.ResetPeer(
            gobgp_pb2.ResetPeerRequest(
                address=address,
                soft=soft,
                direction=direction,
            ),
            self.timeout_seconds,
        )
