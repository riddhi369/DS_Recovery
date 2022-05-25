#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for AWS Cloudwatchlogs Checkpointer.
"""
from __future__ import absolute_import

import json
import re

import splunk_ta_aws.common.ta_aws_consts as tac
import splunktalib.common.util as scutil
import splunktalib.state_store as ss
from splunk_ta_aws.common import pymd5
from splunksdc import logging

from . import aws_cloudwatch_logs_consts as aclc

logger = logging.get_module_logger()


class CloudWatchLogsCheckpointer:
    """Class for Cloudwatchlogs Checkpointer."""

    def __init__(self, config, stream):
        self._key = None
        self._ckpt = None
        if scutil.is_true(config.get(tac.use_kv_store)):
            self._store = ss.get_state_store(
                config,
                config[tac.app_name],
                collection_name=aclc.cloudwatch_logs_log_ns,
                use_kv_store=True,
            )
        else:
            self._store = ss.get_state_store(config, config[tac.app_name])

        self._pop_ckpt(config, stream)

    def _pop_ckpt(self, config, stream):
        stream_name = stream["logStreamName"]
        stanza_name = config[tac.stanza_name]
        region = config[tac.region]
        group_name = config[aclc.log_group_name]

        prefix = re.sub(r"[^\w\d]", "_", stanza_name)
        key = json.dumps([stanza_name, region, group_name, stream_name])
        key = key.encode("utf-8")
        self._key = prefix + "_" + pymd5.md5(key).hexdigest()

        try:
            self._ckpt = self._store.get_state(self._key)
        except Exception:  # pylint: disable=broad-except
            logger.error(
                "Failed to load state for log_group=%s, stream=%s",
                group_name,
                stream_name,
            )

        if self._ckpt is None:
            self._ckpt = {"version": "1.2.0", "start_time": config[aclc.only_after]}

        if "firstEventTimestamp" in stream:
            self._ckpt["start_time"] = max(
                self._ckpt["start_time"], stream["firstEventTimestamp"] - 1
            )

    def start_time(self):
        """Returns start time."""
        return self._ckpt["start_time"]

    def save(self, end_time):
        """Saves start time."""
        self._ckpt["start_time"] = end_time
        self._store.update_state(self._key, self._ckpt)
