#!/usr/bin/env python
#
# Copyright (c) 2019 Mail.ru Group
# Copyright (c) 2018 Mail.ru Group
# Copyright (c) 2014 Eugene Frolov <eugene@frolov.net.ru>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from logging import config as logging_config

import yaml


DEFAULT_CONFIG = {
    'version': 1,
    'formatters': {
        'aardvark': {
            'datefmt': '%Y-%m-%d,%H:%M:%S',
            'format': "%(asctime)15s.%(msecs)03d %(processName)s"
                      " pid:%(process)d tid:%(thread)d %(levelname)s"
                      " %(name)s:%(lineno)d %(message)s"
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'aardvark',
            'stream': 'ext://sys.stderr'
        },
    },
    'loggers': {
    },
    'root': {
        'level': 'DEBUG',
        'handlers': ['console']
    }
}


def configure(service_name, config_file_path=None):

    default_config = DEFAULT_CONFIG.copy()
    default_config['loggers'][service_name] = {}

    if config_file_path is None:
        config_data = default_config
        logging.getLogger(__name__).warning(
            'Logging configuration not found - using defaults')
    else:
        with open(config_file_path) as f:
            config_data = yaml.safe_load(f)

    logging_config.dictConfig(config_data)
