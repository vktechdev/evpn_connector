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


import netaddr


# Bit that indicate that a VLAN id is set.
OFPVID_PRESENT = 0x1000
VLAN_OF_HEADER = "0x8100"


def vid_present(vlan_id):
    """Return VLAN VID with VID_PRESENT flag set"""
    return vlan_id | OFPVID_PRESENT


def push_vlan_action():
    return "push_vlan:%s" % VLAN_OF_HEADER


def get_arp_proxy_responder_action(mac):
    return (
        # Place the source MAC address of the request (The requesting VM)
        # as the new reply's destination MAC address
        "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
        # Put the requested MAC address of the remote VM as source MAC address
        "set_field:%(mac)s->eth_src,"
        # Put an 0x2 code as the type of the ARP message. 0x2 - ARP response.
        "load:0x2->NXM_OF_ARP_OP[],"
        # Place the ARP request's source hardware address (MAC) as this
        # new message"s ARP target / destination hardware address
        "move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],"
        # load arp target protocol address (TPA) of the current packet
        # into register 0 (a special field that is an Open vSwitch
        # extension to OpenFlow)
        "move:NXM_OF_ARP_TPA[]->NXM_NX_REG0[],"
        # Place the ARP request's source protocol / IP address as
        # the new message's ARP destination IP address
        "move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],"
        # load data from register 0 and set it as sender protocol address (SPA)
        "move:NXM_NX_REG0[]->NXM_OF_ARP_SPA[],"
        # Place the requested VM's MAC address as the source MAC address
        "load:%(mac)#x->NXM_NX_ARP_SHA[],"
        # Forward the message back to the port it came in on
        "IN_PORT"
        % {
            "mac": netaddr.EUI(mac, dialect=netaddr.mac_unix_expanded),
        }
    )
