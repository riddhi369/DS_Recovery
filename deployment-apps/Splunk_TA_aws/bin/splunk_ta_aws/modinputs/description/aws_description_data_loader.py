#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for AWS Description Data loader.
"""
from __future__ import absolute_import

import time

import splunk_ta_aws.common.ta_aws_consts as tac
import splunksdc.log as logging
import splunktalib.common.util as scutil

from . import aws_description_consts as adc

logger = logging.get_module_logger()


def get_supported_description_apis():
    """Returns supported description APIs."""

    from . import (  # isort: skip # pylint: disable=import-outside-toplevel
        cloudfront_description as acd,
    )
    from . import ec2_description as ade  # pylint: disable=import-outside-toplevel
    from . import elb_description as aed  # pylint: disable=import-outside-toplevel
    from . import iam_description as aid  # pylint: disable=import-outside-toplevel
    from . import lambda_description as ald  # pylint: disable=import-outside-toplevel
    from . import rds_description as ard  # pylint: disable=import-outside-toplevel
    from . import s3_description as asd  # pylint: disable=import-outside-toplevel
    from . import vpc_description as avd  # pylint: disable=import-outside-toplevel

    return {
        "ec2_instances": ade.ec2_instances,
        "ec2_reserved_instances": ade.ec2_reserved_instances,
        "ebs_snapshots": ade.ec2_ebs_snapshots,
        "ec2_volumes": ade.ec2_volumes,
        "ec2_security_groups": ade.ec2_security_groups,
        "ec2_key_pairs": ade.ec2_key_pairs,
        "ec2_images": ade.ec2_images,
        "ec2_addresses": ade.ec2_addresses,
        "elastic_load_balancers": aed.classic_load_balancers,  # forward-compatibility
        "classic_load_balancers": aed.classic_load_balancers,
        "application_load_balancers": aed.application_load_balancers,
        "vpcs": avd.vpcs,
        "vpc_subnets": avd.vpc_subnets,
        "vpc_network_acls": avd.vpc_network_acls,
        "cloudfront_distributions": acd.cloudfront_distributions,
        "rds_instances": ard.rds_instances,
        "lambda_functions": ald.lambda_functions,
        "s3_buckets": asd.s3_buckets,
        "iam_users": aid.iam_users,
    }


class DescriptionDataLoader:
    """Class for Description Data Loader."""

    def __init__(self, task_config):
        """
        :task_config: dict object
        {
        "interval": 30,
        "api": "ec2_instances" etc,
        "source": xxx,
        "sourcetype": yyy,
        "index": zzz,
        }
        """

        self._task_config = task_config
        self._supported_desc_apis = get_supported_description_apis()
        self._api = self._supported_desc_apis.get(task_config[adc.api], None)
        if self._api is None:
            logger.error(
                "Unsupported service.",
                service=task_config[adc.api],
                ErrorCode="ConfigurationError",
                ErrorDetail="Service is unsupported.",
                datainput=task_config[tac.datainput],
            )

    def __call__(self):
        with logging.LogContext(datainput=self._task_config[tac.datainput]):
            self.index_data()

    def index_data(self):
        """Starts indexing data."""
        logger.info(
            "Start collecting description for service=%s, region=%s",
            self._task_config[adc.api],
            self._task_config[tac.region],
        )
        try:
            self._do_index_data()
        except Exception:  # pylint: disable=broad-except
            logger.exception(
                "Failed to collect description data for %s.", self._task_config[adc.api]
            )
        logger.info(
            "End of collecting description for service=%s, region=%s",
            self._task_config[adc.api],
            self._task_config[tac.region],
        )

    def _do_index_data(self):
        if self._api is None:
            return

        evt_fmt = (
            "<stream><event>"
            "<time>{time}</time>"
            "<source>{source}</source>"
            "<sourcetype>{sourcetype}</sourcetype>"
            "<index>{index}</index>"
            "<data>{data}</data>"
            "</event></stream>"
        )

        task = self._task_config
        results = self._api(task)

        events = []
        size_total = 0
        for result in results:
            event = evt_fmt.format(
                source=task[tac.source],
                sourcetype=task[tac.sourcetype],
                index=task[tac.index],
                data=scutil.escape_cdata(result),
                time=time.time(),
            )
            size_total += len(event)
            events.append(event)
        logger.info(
            "Send data for indexing.",
            action="index",
            size=size_total,
            records=len(events),
        )

        task["writer"].write_events("".join(events))

    def get_interval(self):
        """Returns input interval."""
        return self._task_config[tac.interval]

    def stop(self):
        """Stops the input."""
        pass  # pylint: disable=unnecessary-pass

    def get_props(self):
        """Returns configs."""
        return self._task_config
