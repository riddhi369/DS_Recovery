#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""File for Lamda description for description input."""
from __future__ import absolute_import

import json

import boto3
import splunk_ta_aws.common.ta_aws_consts as tac
import splunksdc.log as logging
from splunk_ta_aws.common.ta_aws_common import is_http_ok

from . import description as desc

logger = logging.get_module_logger()


def get_lambda_client(config):
    """Returns lambda client."""
    return desc.BotoRetryWrapper(
        boto_client=boto3.client(
            "lambda",
            region_name=config[tac.region],
            aws_access_key_id=config[tac.key_id],
            aws_secret_access_key=config[tac.secret_key],
            aws_session_token=config.get("aws_session_token"),
        )
    )


@desc.refresh_credentials  # Already pagination inside
def lambda_functions(config):
    """Yields lambda functions."""
    client = get_lambda_client(config)
    params = {"MaxItems": 1000}
    while True:
        resp = client.list_functions(**params)
        if not is_http_ok(resp):
            logger.error(
                "Fetch Lambda functions failed", response=resp.get("Failed", resp)
            )
        for func in resp.get("Functions", []):
            func[tac.region] = config[tac.region]
            yield json.dumps(func)
        try:
            params["Marker"] = resp["NextMarker"]
        except Exception:  # pylint: disable=broad-except
            break
