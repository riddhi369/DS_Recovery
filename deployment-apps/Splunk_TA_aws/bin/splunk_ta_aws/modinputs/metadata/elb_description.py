#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for ELB description of metadata input.
"""
from __future__ import absolute_import

import datetime

import boto3
import splunk_ta_aws.common.ta_aws_consts as tac
import splunksdc.log as logging
from botocore.exceptions import ClientError

from . import description as desc

logger = logging.get_module_logger()

CREDENTIAL_THRESHOLD = datetime.timedelta(minutes=20)


@desc.generate_credentials
@desc.decorate
def classic_load_balancers(config):
    """Describes classic load balancers."""
    elb_client = desc.BotoRetryWrapper(
        boto_client=boto3.client(
            "elb",
            region_name=config.get(tac.region),
            aws_access_key_id=config.get(tac.key_id),
            aws_secret_access_key=config.get(tac.secret_key),
            aws_session_token=config.get("aws_session_token"),
        )
    )
    paginator = elb_client.get_paginator("describe_load_balancers")

    for page in paginator.paginate():
        all_elbs = page.get("LoadBalancerDescriptions", None)
        if all_elbs is None or len(all_elbs) <= 0:
            continue
        for elb in all_elbs:
            # describe instance health
            try:
                instances = elb_client.describe_instance_health(
                    LoadBalancerName=elb.get("LoadBalancerName", None)
                ).get("InstanceStates", None)
            except Exception:  # pylint: disable=broad-except
                logger.exception(
                    "Ignore ELB due to exception", ELB=elb.get("LoadBalancerName")
                )
                continue
            instances_trans = []
            for instance in instances:
                instance_trans = {
                    "InstanceId": instance.get("InstanceId", None),
                    "State": instance.get("State", None),
                }
                instances_trans.append(instance_trans)
            elb["instances"] = instances_trans

            # describe tags
            try:
                tags_arr = elb_client.describe_tags(
                    LoadBalancerNames=[elb["LoadBalancerName"]]
                ).get("TagDescriptions", None)
            except ClientError as err:  # noqa: F841 # pylint: disable=unused-variable
                tags_arr = None
                logger.exception(
                    "Error in describing classic load balancer tags.",
                    load_balancer_name=elb["LoadBalancerName"],
                )

            if tags_arr is not None and len(tags_arr) > 0:
                elb["Tags"] = tags_arr[0]["Tags"]

            yield elb
        desc.refresh_credentials(config, CREDENTIAL_THRESHOLD, elb_client)


@desc.generate_credentials
@desc.decorate
def application_load_balancers(config):  # pylint: disable=too-many-locals
    """Yields application load balancers."""
    elb_v2_client = desc.BotoRetryWrapper(
        boto_client=boto3.client(
            "elbv2",
            region_name=config[tac.region],
            aws_access_key_id=config.get(tac.key_id),
            aws_secret_access_key=config.get(tac.secret_key),
            aws_session_token=config.get("aws_session_token"),
        )
    )

    alb_paginator = elb_v2_client.get_paginator("describe_load_balancers")

    for page in alb_paginator.paginate():  # pylint: disable=too-many-nested-blocks
        albs = page["LoadBalancers"]
        if albs is not None and len(albs) > 0:
            for alb in albs:

                # fetch tags
                tags_arr = elb_v2_client.describe_tags(
                    ResourceArns=[alb["LoadBalancerArn"]]
                )["TagDescriptions"]
                if tags_arr is not None and len(tags_arr) > 0:
                    alb["Tags"] = tags_arr[0]["Tags"]

                # fetch target groups
                target_groups_paginator = elb_v2_client.get_paginator(
                    "describe_target_groups"
                )
                target_group_list = []

                for target_group_page in target_groups_paginator.paginate(
                    LoadBalancerArn=alb["LoadBalancerArn"]
                ):
                    target_groups = target_group_page["TargetGroups"]
                    if target_groups is not None and len(target_groups) > 0:
                        for target_group in target_groups:
                            # fetch target health
                            target_health_description = (
                                elb_v2_client.describe_target_health(
                                    TargetGroupArn=target_group["TargetGroupArn"]
                                )
                            )
                            target_group[
                                "TargetHealthDescriptions"
                            ] = target_health_description["TargetHealthDescriptions"]

                            target_group_list.append(target_group)

                alb["TargetGroups"] = target_group_list

                # fetch listeners
                # error handling for users upgrading from 4.3,
                # whose IAM settings do not contain the policy "elasticloadbalancing:DescribeListeners"
                try:
                    listeners_paginator = elb_v2_client.get_paginator(
                        "describe_listeners"
                    )
                    listener_list = []

                    for listener_page in listeners_paginator.paginate(
                        LoadBalancerArn=alb["LoadBalancerArn"]
                    ):
                        listeners = listener_page["Listeners"]
                        if listeners is not None and len(listeners) > 0:
                            listener_list.extend(listeners)

                    alb["Listeners"] = listener_list

                except ClientError as err:
                    if (
                        "Code" in err.response["Error"]
                        and err.response["Error"]["Code"] == "AccessDenied"
                    ):
                        logger.warn(  # pylint: disable=deprecated-method
                            'Failed to describe classic load balancer listeners. It requires "elasticloadbalancing:DescribeListeners" IAM policy.'  # pylint: disable=line-too-long
                        )

                yield alb
        desc.refresh_credentials(config, CREDENTIAL_THRESHOLD, elb_v2_client)
