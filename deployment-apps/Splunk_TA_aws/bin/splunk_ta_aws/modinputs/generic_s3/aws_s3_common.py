#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for AWS generic S3 input.
"""
from __future__ import absolute_import

import codecs
import os
import re
from collections import namedtuple
from datetime import datetime

import boto
import boto.s3 as bs
import boto.s3.connection as bsc
import botocore
import splunk_ta_aws.common.ta_aws_consts as tac
import splunksdc.log as logging
from dateutil.parser import parse as parse_timestamp
from splunk_ta_aws.common import boto2_s3_patch

from . import aws_s3_consts as asc

logger = logging.get_module_logger()
BOTO_DATE_FORMAT = r"%Y-%m-%dT%H:%M:%S.000Z"
NOT_FOUND_STATUS = 404

sourcetype_to_keyname_regex = {
    asc.aws_cloudtrail: r"\d+_CloudTrail_[\w-]+_\d{4}\d{2}\d{2}T\d{2}\d{2}Z_.{16}\.json\.gz$",
    asc.aws_elb_accesslogs: r".*\d+_elasticloadbalancing_[\w-]+_.+\.log(\.gz)?$",
    asc.aws_cloudfront_accesslogs: r".+\.\d{4}-\d{2}-\d{2}-\d{2}\..+\.gz$",
    asc.aws_s3_accesslogs: r".+\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-.+$",
}


def _create_s3_connection(config, region):
    calling_format = bsc.OrdinaryCallingFormat()
    if region:
        conn = bs.connect_to_region(
            region,
            aws_access_key_id=config[tac.key_id],
            aws_secret_access_key=config[tac.secret_key],
            security_token=config.get("aws_session_token"),
            proxy=config.get(tac.proxy_hostname),
            proxy_port=config.get(tac.proxy_port),
            proxy_user=config.get(tac.proxy_username),
            proxy_pass=config.get(tac.proxy_password),
            is_secure=True,
            validate_certs=True,
            calling_format=calling_format,
            host=config.get("host_name"),
        )
    else:
        if not os.environ.get("S3_USE_SIGV4") and not config.get(asc.bucket_name):
            calling_format = bsc.SubdomainCallingFormat()

        conn = boto.connect_s3(
            host=config[asc.host_name],
            aws_access_key_id=config[tac.key_id],
            aws_secret_access_key=config[tac.secret_key],
            security_token=config.get("aws_session_token"),
            proxy=config.get(tac.proxy_hostname),
            proxy_port=config.get(tac.proxy_port),
            proxy_user=config.get(tac.proxy_username),
            proxy_pass=config.get(tac.proxy_password),
            is_secure=True,
            validate_certs=True,
            calling_format=calling_format,
        )
    return conn


def _key_id_not_in_records(e):  # pylint: disable=invalid-name
    no_keyid = "The AWS Access Key Id you provided does not exist " + "in our records"
    return e.status == 403 and no_keyid in e.body


def validate_region_and_bucket(region, config):
    """Returns region and bucket."""
    conn = _create_s3_connection(config, region)
    try:
        conn.get_bucket(config[asc.bucket_name])
    except Exception:  # pylint: disable=broad-except
        return False
    return True


def get_region_for_bucketname(config):
    """
    :config: dict
    {
        key_id: xxx (required),
        secret_key: xxx (required),
        host: xxx,
        bucket_name: xxx,
        proxy_hostname: xxx,
        proxy_port: xxx,
        proxy_username: xxx,
        proxy_password: xxx,
    }
    """

    if not config.get(asc.bucket_name):
        if config.get(tac.region):
            return config[tac.region]
        return ""

    if config.get(tac.region):
        res = validate_region_and_bucket(config[tac.region], config)
        if res:
            return config[tac.region]

    conn = _create_s3_connection(config, "us-east-1")
    try:
        conn.get_bucket(config[asc.bucket_name])
    except boto2_s3_patch.RegionRedirection as exc:
        return exc.region_name
    except Exception:
        logger.exception(
            "Failed to detect S3 bucket region.", bucket_name=config[asc.bucket_name]
        )
        raise

    return "us-east-1"


def create_s3_connection(config):
    """
    :config: dict
    {
        key_id: xxx (required),
        secret_key: xxx (required),
        host_name: xxx,
        bucket_name: xxx,
        region: xxx,
        proxy_hostname: xxx,
        proxy_port: xxx,
        proxy_username: xxx,
        proxy_password: xxx,
    }
    """

    if not config.get(asc.host_name):
        config[asc.host_name] = asc.default_host

    if config[asc.host_name] == asc.default_host:
        config[tac.region] = get_region_for_bucketname(config)
    else:
        pattern = r"s3[.-]([\w-]+)\.amazonaws.com"
        match = re.search(pattern, config[asc.host_name])
        if match:
            config[tac.region] = match.group(1)
        else:
            config[tac.region] = "us-east-1"
    return _create_s3_connection(config, config[tac.region])


def _build_regex(regex_str):
    if regex_str:
        exact_str = regex_str if regex_str[-1] == "$" else regex_str + "$"
        return re.compile(exact_str)
    else:
        return None


def format_utc_datetime(dt):  # pylint: disable=invalid-name
    """Returns formatted UTC datetime."""
    if not dt:
        return dt

    dt = dt.strip()
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    if not dt.endswith(".000Z"):
        fmt = "%Y-%m-%dT%H:%M:%S"
    return datetime.strptime(dt, fmt)


def _match_regex(white_matcher, black_matcher, key):
    if white_matcher is not None:
        if white_matcher.search(key["Key"]):
            return True
    else:
        if black_matcher is None or not black_matcher.search(key["Key"]):
            return True
    return False


class TupleMaker:
    """Class for Tuple Maker."""

    def __init__(self, typename, recipe):
        self._recipe = recipe
        self._type = namedtuple(typename, recipe.keys())

    def __call__(self, record, **kwargs):
        params = {key: getter(record) for key, getter in self._recipe.items()}
        params.update(kwargs)
        return self._type(**params)

    @classmethod
    def boto_key_adaptor(cls, arg):
        """Adaptor layer for using boto style access."""
        adaptor = cls(
            "BotoKeyAdaptor",
            {
                "body": lambda _: _.get("Body"),
                "name": lambda _: _.get("Key"),
                "size": lambda _: _.get("Size", _.get("ContentLength")),
                "etag": lambda _: _.get("ETag", "").strip('"'),
                "last_modified": lambda _: _["LastModified"].strftime(BOTO_DATE_FORMAT),
                "storage_class": lambda _: _.get("StorageClass"),
            },
        )
        return adaptor(arg)


def get_keys(  # pylint: disable=too-many-arguments
    refresh_creds_func,
    s3_conn,
    bucket,
    prefix="",
    whitelist=None,
    blacklist=None,
    last_modified=None,
    storage_classes=("STANDARD", "STANDARD_IA", "REDUCED_REDUNDANCY"),
):
    """Returns keys."""
    if prefix is None:
        prefix = ""
    black_matcher = _build_regex(blacklist)
    white_matcher = _build_regex(whitelist)

    paginator = s3_conn.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for key in page.get("Contents", []):
            key_last_modified = key["LastModified"].strftime(BOTO_DATE_FORMAT)

            if (not last_modified) or (key_last_modified >= last_modified):

                if _match_regex(white_matcher, black_matcher, key):

                    if storage_classes and key["StorageClass"] not in storage_classes:
                        logger.warning(
                            "Skipped this key because storage class does not match"
                            "(only supports STANDARD, STANDARD_IA and REDUCED_REDUNDANCY).",
                            key_name=key["Key"],
                            storage_class=key["StorageClass"],
                        )
                        continue

                    yield TupleMaker.boto_key_adaptor(key)

        refresh_creds_func()


def get_key(s3_conn, bucket, key, byte_range=None):
    """Returns key"""
    try:
        res = {}
        if byte_range:
            res = s3_conn.get_object(Bucket=bucket, Key=key, Range=byte_range)
        else:
            res = s3_conn.get_object(Bucket=bucket, Key=key)
        res["Key"] = key
        return TupleMaker.boto_key_adaptor(res)
    except botocore.exceptions.ClientError as err:
        if err.response["ResponseMetadata"]["HTTPStatusCode"] == NOT_FOUND_STATUS:
            return None
        raise


def detect_unicode_by_bom(data):
    """Detects encoding."""
    if data[:2] == b"\xFE\xFF":
        return "UTF-16BE"
    if data[:2] == b"\xFF\xFE":
        return "UTF-16LE"
    if data[:4] == b"\x00\x00\xFE\xFF":
        return "UTF-32BE"
    if data[:4] == b"\xFF\xFE\x00\x00":
        return "UTF-32LE"
    return "UTF-8"


def get_decoder(encoding, data):
    """Returns decoder."""
    if not encoding:
        if data:
            encoding = detect_unicode_by_bom(data)
        else:
            encoding = "UTF-8"

    try:
        decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
        return decoder, encoding
    except LookupError:
        decoder = codecs.getincrementaldecoder("UTF-8")(errors="replace")
        return decoder, encoding


def normalize_to_iso8601(time_string):
    """Returns normalised date time."""
    date_time = parse_timestamp(time_string)
    return date_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
