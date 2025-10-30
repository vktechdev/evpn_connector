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

from obsender import multi_sender
from obsender import senders
from oslo_config import cfg


CONF = cfg.CONF


def construct_event_sender(app_name, logger=None, timeout=None):
    """Construct dummy event sender for loopster.

    """
    if timeout is None:
        timeout = 2.0

    common_kwargs = {
        "app_name": app_name,
        "logger": logger,
        "timeout": timeout,
    }

    return senders.DummySender(**common_kwargs)


def construct_metric_sender(app_name, logger=None):
    return senders.VictoriaMetricSender(
        app_name=app_name,
        enabled=CONF.victoria_metrics.enabled,
        prefix=CONF.victoria_metrics.prefix,
        host=CONF.victoria_metrics.host,
        port=CONF.victoria_metrics.port,
        global_tags={"host": CONF.victoria_metrics.obsender_host},
        obsender_host=CONF.victoria_metrics.obsender_host,
        logger=logger,
    )


def get_sender(app_name, logger=None, timeout=None):
    event_sender = construct_event_sender(app_name, logger, timeout)
    metric_sender = construct_metric_sender(app_name, logger)
    return multi_sender.MultiSender([metric_sender], [event_sender])
