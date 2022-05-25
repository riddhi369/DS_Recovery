#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""File for Lamda description for metadata input."""
from __future__ import absolute_import

import datetime

import boto3
import splunk_ta_aws.common.ta_aws_consts as tac
import splunksdc.log as logging

from . import description as desc

logger = logging.get_module_logger()

CREDENTIAL_THRESHOLD = datetime.timedelta(minutes=20)


def get_lambda_conn(config):
    """Returns lambda connection."""
    return desc.BotoRetryWrapper(
        boto_client=boto3.client(
            "lambda",
            region_name=config[tac.region],
            aws_access_key_id=config[tac.key_id],
            aws_secret_access_key=config[tac.secret_key],
            aws_session_token=config.get("aws_session_token"),
        )
    )


@desc.generate_credentials
@desc.decorate
def lambda_functions(config):
    """Yields lambda functions."""
    lambda_conn = get_lambda_conn(config)
    paginator = lambda_conn.get_paginator("list_functions")

    for page in paginator.paginate():
        for function in page.get("Functions", []):
            yield function
        desc.refresh_credentials(config, CREDENTIAL_THRESHOLD, lambda_conn)
