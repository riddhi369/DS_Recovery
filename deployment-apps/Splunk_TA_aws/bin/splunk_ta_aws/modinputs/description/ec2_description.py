#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for EC2 description of description input
"""
from __future__ import absolute_import

import os

import boto3
import boto.ec2
import splunk_ta_aws.common.ta_aws_common as tacommon
import splunk_ta_aws.common.ta_aws_consts as tac
import splunksdc.log as logging
from boto.ec2.snapshot import Snapshot
from boto.exception import BotoServerError

from . import description as desc

logger = logging.get_module_logger()


EC2_IMAGE_KEYS = [
    "id",
    "location",
    "state",
    "owner_id",
    "owner_alias",
    "is_public",
    "architecture",
    "platform",
    "type",
    "kernel_id",
    "ramdisk_id",
    "name",
    "description",
    "product_codes",
    "billing_products",
    "root_device_type",
    "root_device_name",
    "virtualization_type",
    "hypervisor",
    "instance_lifecycle",
    "sriov_net_support",
]


def connect_ec2_to_region(config):
    """Returns connection from EC2 to region."""
    return desc.BotoRetryWrapper(
        boto_client=tacommon.connect_service_to_region(
            boto.ec2.connect_to_region, config
        )
    )


_TA_AWS_MAX_RESULTS = int(os.environ.get("TA_AWS_DESCRIPTION_MAX_RESULTS", 500))


def _describe_snapshots(  # pylint: disable=too-many-arguments
    conn,
    snapshot_ids=None,
    owner=None,
    restorable_by=None,
    filters=None,
    dry_run=False,
    max_result=_TA_AWS_MAX_RESULTS,
    next_token=None,
):
    """
    The original interface (conn.get_all_snapshots) doesn't support pagination.
    it will cause problem when there're a lots of snapshots.
    We workaround the limitation by re-implement it base on boto2 public interfaces,
    and expose parameters for pagination.
    """

    params = {"MaxResults": max_result}
    if next_token:
        params["NextToken"] = next_token

    # following lines just copy from boto2 codebase. except the line for logging.
    if snapshot_ids:
        conn.build_list_params(params, snapshot_ids, "SnapshotId")

    if owner:
        conn.build_list_params(params, owner, "Owner")
    if restorable_by:
        conn.build_list_params(params, restorable_by, "RestorableBy")
    if filters:
        conn.build_filter_params(params, filters)
    if dry_run:
        params["DryRun"] = "true"
    logger.debug("Start describing snapshots", **params)
    return conn.get_list("DescribeSnapshots", params, [("item", Snapshot)], verb="POST")


def _get_image_attributes(ec2_conn, image_id):
    try:
        image_attributes = ec2_conn.get_image(image_id)
    except BotoServerError as err:
        image_attributes = None
        error_code = getattr(
            err, "error_code", "an unknown BotoServerError was returned"
        )
        logger.warn(  # pylint: disable=deprecated-method
            "get_image has failed because %s.", error_code
        )
    return image_attributes


@desc.describe_pagination
@desc.refresh_credentials
def ec2_instances(config, **kwargs):
    """Returns EC2 instances results."""
    keys = [
        "state",
        "state_code",
        "previous_state",
        "previous_state_code",
        "placement",
        "placement_group",
        "placement_tenancy",
        "ami_launch_index",
        "architecture",
        "client_token",
        "dns_name",
        "ebs_optimized",
        "group_name",
        "hypervisor",
        "id",
        "image_id",
        "instance_profile",
        "instance_type",
        "ip_address",
        "item",
        "kernel",
        "key_name",
        "launch_time",
        "monitored",
        "monitoring",
        "monitoring_state",
        "persistent",
        "platform",
        "private_dns_name",
        "private_ip_address",
        "public_dns_name",
        "reason",
        "root_device_name",
        "root_device_type",
        "sourceDestCheck",
        "spot_instance_request_id",
        "subnet_id",
        "tags",
        "virtualization_type",
        "vpc_id",
    ]

    ec2_conn = connect_ec2_to_region(config)
    reservations = ec2_conn.get_all_reservations(**kwargs)
    pagination = {"next_token": reservations.next_token}

    results = []

    for reservation in reservations:
        instances = reservation.instances
        for instance in instances:
            result = desc.pop_description_result(
                instance,
                keys,
                {
                    "owner_id": reservation.owner_id,
                    tac.account_id: config[tac.account_id],
                },
            )
            results.append(result)
    return results, pagination


@desc.describe_pagination  # No pagination
@desc.refresh_credentials
def ec2_reserved_instances(config):
    """Returns EC2 reserved instances results."""
    ec2_client = desc.BotoRetryWrapper(
        boto_client=boto3.client(
            "ec2",
            region_name=config.get(tac.region),
            aws_access_key_id=config.get(tac.key_id),
            aws_secret_access_key=config.get(tac.secret_key),
            aws_session_token=config.get("aws_session_token"),
        )
    )

    keys = [
        "ReservedInstancesId",
        "OfferingType",
        "InstanceCount",
        "AvailabilityZone",
        "InstanceType",
        "InstanceTenancy",
        "State",
        "FixedPrice",
        "ProductDescription",
        "UsagePrice",
        "CurrencyCode",
        "Start",
        "End",
        "Duration",
        "Scope",
    ]

    reserved_instances = ec2_client.describe_reserved_instances()["ReservedInstances"]
    results = desc.pop_description_results(
        reserved_instances,
        keys,
        {tac.account_id: config[tac.account_id], tac.region: config[tac.region]},
        pop_region_name=False,
    )

    return results, {}


# boto3 supports pagination
@desc.describe_pagination
@desc.refresh_credentials
def ec2_ebs_snapshots(config, **kwargs):
    """Returns EC2 EBS snapshots results."""
    keys = [
        "description",
        "encrypted",
        "id",
        "item",
        "owner_alias",
        "owner_id",
        "progress",
        "start_time",
        "status",
        "tags",
        "volume_id",
        "volume_size",
    ]

    ec2_conn = connect_ec2_to_region(config)

    snapshots = _describe_snapshots(ec2_conn, owner="self", **kwargs)
    pagination = {"next_token": snapshots.next_token}

    results = desc.pop_description_results(
        snapshots, keys, {tac.account_id: config[tac.account_id]}
    )

    return results, pagination


# boto3 supports pagination
@desc.describe_pagination
@desc.refresh_credentials
def ec2_volumes(config):
    """Returns EC2 volumes results."""
    vol_keys = [
        "attach_data",
        "encrypted",
        "type",
        "id",
        "status",
        "snapshot_id",
        "size",
        "iops",
        "tags",
        "create_time",
        "zone",
    ]
    attach_keys = [
        "attach_time",
        "deleteOnTermination",
        "device",
        "id",
        "instance_id",
        "status",
    ]

    ec2_conn = connect_ec2_to_region(config)
    volumes = ec2_conn.get_all_volumes()

    results = desc.pop_description_results(
        volumes, vol_keys, {tac.account_id: config[tac.account_id]}, raw_event=True
    )
    for i, result in enumerate(results):
        attach = desc.pop_description_result(
            result["attach_data"],
            attach_keys,
            {},
            pop_region_name=False,
            raw_event=True,
        )
        result["attach_data"] = attach
        results[i] = desc.serialize(result)
    return results, {}


@desc.describe_pagination  # No pagination
@desc.refresh_credentials
def ec2_security_groups(config):
    """Returns EC2 Security groups results."""
    cg_keys = [
        "description",
        "id",
        "instances",
        "name",
        "owner_id",
        "rules_egress",
        "rules",
        "tags",
        "vpc_id",
    ]

    ec2_conn = connect_ec2_to_region(config)
    cgs = ec2_conn.get_all_security_groups()

    results = desc.pop_description_results(
        cgs, cg_keys, {tac.account_id: config[tac.account_id]}, raw_event=True
    )

    for i, result in enumerate(results):
        result["rules_egress"] = _pop_rules(result["rules_egress"])
        result["rules"] = _pop_rules(result["rules"])
        instances = desc.pop_description_results(
            result["instances"](), ["id"], {}, pop_region_name=False, raw_event=True
        )
        result["instances"] = instances
        results[i] = desc.serialize(result)

    return results, {}


def _pop_rules(rules):
    rule_keys = ["from_port", "grants", "groups", "ipRanges", "ip_protocol", "to_port"]
    grant_keys = ["cidr_ip", "group_id", "name", "owner_id"]

    rule_results = desc.pop_description_results(
        rules, rule_keys, {}, pop_region_name=False, raw_event=True
    )
    for rule in rule_results:
        rule["grants"] = desc.pop_description_results(
            rule["grants"], grant_keys, {}, pop_region_name=False, raw_event=True
        )
    return rule_results


@desc.describe_pagination  # No pagination
@desc.refresh_credentials
def ec2_key_pairs(config):
    """Returns EC2 pairs results."""
    keys = ["name", "fingerprint"]

    ec2_conn = connect_ec2_to_region(config)
    key_pairs = ec2_conn.get_all_key_pairs()

    results = desc.pop_description_results(
        key_pairs, keys, {tac.account_id: config[tac.account_id]}
    )
    return results, {}


@desc.describe_pagination  # No pagination
@desc.refresh_credentials
def ec2_images(config):
    """Returns EC2 images results."""
    ec2_conn = connect_ec2_to_region(config)

    images = ec2_conn.get_all_images(owners="self")

    results = desc.pop_description_results(
        images, EC2_IMAGE_KEYS, {tac.account_id: config[tac.account_id]}
    )

    return results, {}


@desc.describe_pagination  # No pagination
@desc.refresh_credentials
def ec2_addresses(config):
    """Returns EC2 address results."""
    keys = [
        "public_ip",
        "instance_id",
        "domain",
        "allocation_id",
        "association_id",
        "network_interface_id",
        "network_interface_owner_id",
        "private_ip_address",
    ]

    ec2_conn = connect_ec2_to_region(config)

    addresses = ec2_conn.get_all_addresses()

    results = desc.pop_description_results(
        addresses, keys, {tac.account_id: config[tac.account_id]}
    )

    return results, {}
