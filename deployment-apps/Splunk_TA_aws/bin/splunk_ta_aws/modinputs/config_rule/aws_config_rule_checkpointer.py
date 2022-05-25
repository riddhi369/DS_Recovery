#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for checkpoint handling for AWS config rule input.
"""
from __future__ import absolute_import

import base64
import time

import splunk_ta_aws.common.ta_aws_consts as tac
import splunktalib.state_store as ss


class AWSConfigRuleCheckpointer:
    """Class for AWS Config rule checkpointer."""

    def __init__(self, config):
        self._config = config
        self._state_store = ss.get_state_store(
            config,
            config[tac.app_name],
            collection_name="aws_config_rule",
            use_kv_store=config.get(tac.use_kv_store),
        )

    def last_evaluation_time(  # pylint: disable=inconsistent-return-statements
        self, region, datainput, rule_name
    ):
        """Returns last evaluation time for checkpoint"""
        key = base64.b64encode(
            "{}|{}|{}".format(  # pylint: disable=consider-using-f-string
                region, datainput, rule_name
            ).encode()
        )
        state = self._state_store.get_state(key.decode("utf-8"))
        if state:
            return state["last_evaluation_time"]

    def set_last_evaluation_time(self, region, datainput, rule_name, etime):
        """Sets last evaluation time for checkpoint."""
        key = base64.b64encode(
            "{}|{}|{}".format(  # pylint: disable=consider-using-f-string
                region, datainput, rule_name
            ).encode()
        )
        state = {
            "last_evaluation_time": etime,
            "timestamp": time.time(),
            "version": 1,
        }
        self._state_store.update_state(key.decode("utf-8"), state)
