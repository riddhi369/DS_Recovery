#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
from __future__ import absolute_import
import splunksdc.log as logging

__version__ = "1.0"

logger = logging.get_module_logger()
logger.set_level(logging.INFO)


def set_log_level(level):
    logger.set_level(level)
