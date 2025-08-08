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

import logging
import sys

from oslo_config import cfg
from evpn_connector.common import log as evpn_log

from evpn_connector.bgp import client as bgp_client
from evpn_connector.common import conf_opts
from evpn_connector.common import config
from evpn_connector.common import constants
from evpn_connector.common import metrics
from evpn_connector.common import sentry
from evpn_connector.ovs import client as ovs_client
from evpn_connector.service import evpn


OBSENDER_APP_NAME = constants.GLOBAL_SERVICE_NAME
EVENT_TYPE = "%s.service.soft_irq.iteration_step" % OBSENDER_APP_NAME
ERROR_EVENT_TYPE = "%s.error" % EVENT_TYPE
SENTRY_SERVICE_NAME = "%s_%s" % (constants.GLOBAL_SERVICE_NAME, "connector")

CONF = cfg.CONF

conf_opts.register_victoria_metrics_opts()
conf_opts.register_sentry_opts()
conf_opts.register_logging_opts()
conf_opts.register_daemon_opts()
conf_opts.register_gobgp_opts()
conf_opts.register_ovs_opts()
conf_opts.register_anycast_opts()


def main():
    # Parse config
    config.parse(sys.argv[1:])

    sentry.setup_sentry(service=SENTRY_SERVICE_NAME)

    # Configure logging
    evpn_log.configure(
        service_name=constants.GLOBAL_SERVICE_NAME,
        config_file_path=CONF.find_file(CONF.logging.config),
    )

    log = logging.getLogger(__name__)
    sender = metrics.get_sender(OBSENDER_APP_NAME, log)

    # Init gobgp client
    gobgp_client = bgp_client.BGPClient(
        gobgp_channel=CONF.gobgp.gobgp_channel,
        grpc_timeout_sec=CONF.gobgp.grpc_timeout_sec,
        router_mac_type5=CONF.gobgp.router_mac_type5,
    )

    # Init ovs client
    shell_ovs_client = ovs_client.OvSClient(
        sw_name=CONF.ovs.switch_name,
        tmp_flow_file_path=CONF.ovs.tmp_flow_file_path,
        enable_sudo=CONF.ovs.enable_sudo,
        ovsvsctl_bin=CONF.ovs.ovs_vsctl_bin_path,
        ovsofctl_bin=CONF.ovs.ovs_ofctl_bin_path,
    )

    # Start service
    service = evpn.EvpnConnectorService(
        gobgp_client=gobgp_client,
        ovs_client=shell_ovs_client,
        source_ip=CONF.gobgp.source_ip,
        vxlan_udp_port=CONF.ovs.vxlan_udp_port,
        as_number=CONF.gobgp.as_number,
        policy_enabled=CONF.gobgp.policy_enabled,
        configs_dir=CONF.daemon.configs_dir,
        router_mac_type5=CONF.gobgp.router_mac_type5,
        anycast_status_file=CONF.anycast.anycast_status_file,
        anycast_check_ofport=CONF.anycast.anycast_check_ofport,
        anycast_check_mac=CONF.anycast.anycast_check_mac,
        sender=sender,
        step_period=CONF.daemon.sync_period,
        event_type=EVENT_TYPE,
        error_event_type=ERROR_EVENT_TYPE,
    )
    log.info("Start %s service as daemon", constants.GLOBAL_SERVICE_NAME)
    service.serve()
    log.info("Stop %s service.", constants.GLOBAL_SERVICE_NAME)


if __name__ == "__main__":
    main()
