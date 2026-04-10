#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Task """

import logging

from centry_logging.handlers.eventnode import EventNodeLogHandler  # pylint: disable=E0611,E0401
from centry_logging.formatters.secret import SecretFormatter  # pylint: disable=E0611,E0401
from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import context  # pylint: disable=E0401


class make_logger:  # pylint: disable=C0103
    """ Task """

    def __init__(self):
        return

    def __enter__(self):
        return log

    def __exit__(self, exc_type, exc_value, exc_traceback):
        return
