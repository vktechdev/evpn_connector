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

# project
GLOBAL_SERVICE_NAME = "evpn"

# sentry
SENTRY = "sentry"
CONF_GROUP_SENTRY = SENTRY

# logging
DEFAULT_LOGGING_CONFIG_NAME = "logging.yaml"

# addresses
LOCALHOST_ADDRESS = "127.0.0.1"

# Paths for binary
IPROUTE_BIN = "/usr/bin/ip"
OVSVSCTL_BIN = "/usr/bin/ovs-vsctl"
OVSOFCTL_BIN = "/usr/bin/ovs-ofctl"

# OVS params
# Last ofport number
VXLAN_PORT_OFPORT = 65278
ANYCAST_PORT_OFPORT = 65277
UNKNOWN_OFPORT = -1

# Numbers for ovs tables used
INPUT_FILTER_TABLE_NUM = 0
OUTPUT_TABLE_NUM = 1
ECMP_TABLE_NUM = 2
# Priority for flows
NORMAL_PRIO = 10
LOW_PRIO = 9
LOWEST_ACTION_PRIO = 0
# Traffic direction in REG1
REG_FROM_REMOTE = 0
REG_FROM_LOCAL = 1
# ECMP Multipath hash algorithm (for details see man 7 ovs-actions: multipath)
ECMP_HASH_ALGORITHM = "symmetric_l3l4+udp"

# Supported Config types
CONFIG_L2_EVPN = "l2"
CONFIG_L3_EVPN = "l3"
SUPPORTED_CONFIG_TYPES = [CONFIG_L2_EVPN, CONFIG_L3_EVPN]

# EVPN announce types
EVPN_MACADV_TYPE = "macadv"
EVPN_MULTICAST_TYPE = "multicast"
EVPN_PREFIX_TYPE = "Prefix"
EVPN_PREFIX_TYPES = [EVPN_MACADV_TYPE, EVPN_MULTICAST_TYPE, EVPN_PREFIX_TYPE]
MIN_VXLAN_VNI = 1
MAX_VXLAN_VNI = 2**24 - 1

# EVPN Type 5 announce params
TYPE_5_DEFAULT_ROUTER_MAC_EXTENDED = "12:34:56:78:90:ab"
# MAC for L3 networks arp responder
ARP_PROXY_MAC = TYPE_5_DEFAULT_ROUTER_MAC_EXTENDED

# Allowed CE connection types
EVPN_EDGE_TYPE_VLAN = "vlan"
EVPN_EDGE_TYPE_VXLAN = "vxlan"
EVPN_EDGE_TYPE_FLAT = "flat"
ALLOWED_CE_PORT_TYPES = [
    EVPN_EDGE_TYPE_VLAN,
    EVPN_EDGE_TYPE_VXLAN,
    EVPN_EDGE_TYPE_FLAT,
]

# DEFAULT part RT override to asn_local
RT_DEFAULT_FIRST_PART = "0"

# Anycast params
# Default dst mac for anycast checks traffic
ANYCAST_CHECKS_DST_MAC = "12:34:56:78:90:aa"
