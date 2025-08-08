#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2018 Eugene Frolov <eugene@frolov.net.ru>.
#
# All Rights Reserved.
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
from os import path

import wget

URL = 'https://netix.dl.sourceforge.net/project/plantuml/plantuml.jar'
OUTPUT_PATH = '/tmp/plantuml.jar'

logging.basicConfig(level=logging.INFO)


if __name__ == '__main__':
    logging.info("Checking PlantUML files...")
    if not path.exists(OUTPUT_PATH):
        logging.info("Downloading plantuml.jar from %s", URL)
        wget.download(url=URL, out=OUTPUT_PATH)
        logging.info("Downloaded and saved to %s", OUTPUT_PATH)
    logging.info("Done!")
