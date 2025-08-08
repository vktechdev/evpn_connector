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

import obsender.constants

from oslo_config import cfg

from evpn_connector.common import constants


CONF = cfg.CONF

LOGGING_DOMAIN = "logging"
VICTORIA_METRICS_DOMAIN = obsender.constants.VICTORIA_METRICS_DOMAIN
DAEMON_DOMAIN = "daemon"
GOBGP_DOMAIN = "gobgp"
OVS_DOMAIN = "ovs"
SENTRY_DOMAIN = "sentry"
ANYCAST_DOMAIN = "anycast"

logging_opts = [
    cfg.StrOpt(
        name="config",
        default=constants.DEFAULT_LOGGING_CONFIG_NAME,
        help="Logging subsystem configuration YAML file",
    ),
]

victoria_metrics_opts = [
    cfg.BoolOpt("enabled", default=False, help="Enable sending of metrics"),
    cfg.StrOpt("host", help="Specifies host to send metrics for"),
    cfg.IntOpt("port", help="Specifies port to send metrics for"),
    cfg.StrOpt("prefix", help="Specifies metric prefix for send"),
    cfg.StrOpt("obsender_host", help="Specifies host to send metrics for"),
]

daemon_opts = [
    cfg.IntOpt(
        name="sync_period", default=3, help="Sync bgp announces period"
    ),
    cfg.StrOpt(
        name="configs_dir",
        required=True,
        help="Path to evpn client edge configs",
    ),
]

gobgp_opts = [
    cfg.StrOpt(
        name="gobgp_channel",
        default="localhost:50051",
        help="gobgp grpc host:port",
    ),
    cfg.StrOpt(
        name="source_ip",
        required=True,
        help="Source ip for all EVPN traffic and next_hop for BGP announces",
    ),
    cfg.IntOpt(name="as_number", default=1, help="AS number"),
    cfg.IntOpt(
        name="grpc_timeout_sec",
        default=30,
        help="GoBGP grpc timeout in seconds",
    ),
    cfg.BoolOpt(
        name="policy_enabled",
        default=True,
        help="Enable policy to filter import routes",
    ),
    cfg.StrOpt(
        name="router_mac_type5",
        default=constants.TYPE_5_DEFAULT_ROUTER_MAC_EXTENDED,
        help="Value of RouterMacExtended Ext Communities Attr for Type5",
    ),
]

ovs_opts = [
    cfg.StrOpt(
        name="switch_name", required=True, help="OpenvSwitch switch name"
    ),
    cfg.StrOpt(
        name="tmp_flow_file_path",
        default="/tmp/evpn_tmp_flow_file",
        help="Path to tmp file with ovs flows",
    ),
    cfg.StrOpt(
        name="ovs_vsctl_bin_path",
        default=constants.OVSVSCTL_BIN,
        help="Path to ovs-vsctl binary",
    ),
    cfg.StrOpt(
        name="ovs_ofctl_bin_path",
        default=constants.OVSOFCTL_BIN,
        help="Path to ovs-ofctl binary",
    ),
    cfg.BoolOpt(
        name="enable_sudo",
        default=False,
        help="Enable sudo for all commands to OvS",
    ),
    cfg.IntOpt(
        name="vxlan_udp_port",
        default=4789,
        help="Port number for VXLAN traffic",
    ),
]
anycast_opts = [
    cfg.StrOpt(
        name="anycast_status_file",
        default="/tmp/anycast_status_file",
        help="Path to file with anycast ip statuses from anycast-checker",
    ),
    cfg.IntOpt(
        name="anycast_check_ofport",
        default=constants.ANYCAST_PORT_OFPORT,
        help="OvS ofport number for traffic from anycast-checker",
    ),
    cfg.StrOpt(
        name="anycast_check_mac",
        default=constants.ANYCAST_CHECKS_DST_MAC,
        help="Dst MAC address for anycast-checker traffic",
    ),
]

sentry_opts = [
    cfg.BoolOpt(name="enabled", default=False, help="Set True to enable"),
    cfg.StrOpt(
        name="dsn",
        default="http://<token>@192.168.220.220:9000/<project_id>",
        help="DSN URI to sentry server",
    ),
    cfg.FloatOpt(
        name="traces-sample-rate",
        default=1.0,
        help=(
            "Set traces_sample_rate to 1.0 to capture 100% of "
            "transactions for performance monitoring. We recommend "
            "adjusting this value in production."
        ),
    ),
    cfg.StrOpt(
        name="env",
        default="devenv",
        help=(
            "Environment mark for sentry tagging "
            "and applying env-specific rules"
        ),
    ),
]


def register_logging_opts():
    CONF.register_cli_opts(logging_opts, LOGGING_DOMAIN)


def register_victoria_metrics_opts():
    CONF.register_cli_opts(victoria_metrics_opts, VICTORIA_METRICS_DOMAIN)


def register_daemon_opts():
    CONF.register_cli_opts(daemon_opts, DAEMON_DOMAIN)


def register_gobgp_opts():
    CONF.register_cli_opts(gobgp_opts, GOBGP_DOMAIN)


def register_ovs_opts():
    CONF.register_cli_opts(ovs_opts, OVS_DOMAIN)


def register_sentry_opts(conf=CONF):
    conf.register_opts(sentry_opts, constants.CONF_GROUP_SENTRY)


def register_anycast_opts():
    CONF.register_cli_opts(anycast_opts, ANYCAST_DOMAIN)


def list_opts():
    return [
        (LOGGING_DOMAIN, logging_opts),
        (VICTORIA_METRICS_DOMAIN, victoria_metrics_opts),
        (DAEMON_DOMAIN, daemon_opts),
        (GOBGP_DOMAIN, gobgp_opts),
        (OVS_DOMAIN, ovs_opts),
        (SENTRY_DOMAIN, sentry_opts),
        (ANYCAST_DOMAIN, anycast_opts),
    ]
