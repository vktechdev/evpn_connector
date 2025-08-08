#  coding=utf-8
#
#  Copyright 2025 VK Cloud.
#
#  All Rights Reserved.
#
#     Licensed under the Apache License, Version 2.0 (the "License"); you may
#     not use this file except in compliance with the License. You may obtain
#     a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#     WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#     License for the specific language governing permissions and limitations
#     under the License.

import logging

from loopster.services import softirq

LOG = logging.getLogger(__name__)


class SoftIrqServiceMetrics(softirq.SoftIrqService):
    def _send_event(self, name, event_data, skip=False):
        if self._sender is None:
            self._l(LOG).debug("No sender - skipping event: %s", event_data)
        else:
            if skip:
                self._l(LOG).debug("Skipping send metric: %s", name)
                return
            self._sender.send_duration(name.replace(".", "_"), event_data)

    def _send_step_event(self, event_data):
        self._send_event(
            name="soft_irq.duration.step",
            event_data=event_data["duration"].total_seconds(),
            skip=event_data["skipped"],
        )

    def _send_exc_step_event(self, exc_event_data):
        self._l(LOG).debug("Exception even data: %s", exc_event_data)
        self._sender.send_counter("soft_irq_duration_step.error", value=1)

    def _send_wd_error_event(self, wderr_event_data):
        if wderr_event_data.get("minor"):
            self._l(LOG).debug(
                "Can't use old metrics send: %s", wderr_event_data
            )
        else:
            self._l(LOG).warning(
                "Can't use old metrics send: %s", wderr_event_data
            )
