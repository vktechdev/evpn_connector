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

'''
Evpn config example
{
        "mac": "36:e7:a5:7e:0c:8d",
        "ip": "",
        "vni": 10,
        "ofport": 1000,
        "type": "flat",
        "tag": 0,
        "imp_rt": [[65000, 10], [65100, 20]],
        "exp_rt": [[65000, 10]]
}
'''


import json
import netaddr
import os
import sys


PORT_TYPE = "flat"
PORT_TAG = 0
DEFAULT_RT_ASN = 65000
VNI_START = 10
START_MAC = "36:e7:a5:00:00:01"
DEFAULT_NETMASK = 16
START_OFPORT = 33000


def main():
    _, vnet_count, ce_per_vnet, start_prefix, config_dir = sys.argv
    mac = netaddr.EUI(START_MAC).value
    ofport = START_OFPORT
    for vni in range(VNI_START, VNI_START + int(vnet_count)):
        start_ip = netaddr.IPAddress(start_prefix).value
        for ip in range(start_ip, start_ip + int(ce_per_vnet)):
            str_ip = str(netaddr.IPAddress(ip))
            str_mac = netaddr.EUI(mac).format(dialect=netaddr.mac_unix_expanded)
            cfg = {
                "mac": str_mac,
                "ip": str_ip,
                "vni": vni,
                "ofport": ofport,
                "type": PORT_TYPE,
                "tag": PORT_TAG,
                "imp_rt": ["%d:%d" % (DEFAULT_RT_ASN, vni)],
                "exp_rt": ["%d:%d" % (DEFAULT_RT_ASN, vni)],
            }
            fl_name = '%s_%s_%d.json' % (
                str_ip.replace('.', '_'), str_mac.replace(':', '_'), vni)
            cfg_path = os.path.join(config_dir, fl_name)
            with open(cfg_path, 'w') as cfgfl:
                json.dump(cfg, cfgfl)
            mac += 1
            ofport += 1


if __name__ == '__main__':
    main()
