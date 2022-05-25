#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for AWS Billing Cur input.
"""
from __future__ import absolute_import

import csv
import itertools
import json
import json.encoder
import re
import tempfile
import time
from datetime import timedelta

import splunk_ta_aws.common.ta_aws_common as tacommon
from six import BytesIO
from six.moves import zip
from splunk_ta_aws import set_log_level
from splunk_ta_aws.common.proxy import ProxySettings
from splunk_ta_aws.common.s3 import S3Bucket
from splunksdc import logging
from splunksdc.archive import ArchiveFactory
from splunksdc.collector import SimpleCollectorV1

from splunk_ta_aws.common.credentials import (  # isort: skip # pylint: disable=ungrouped-imports
    AWSCredentialsCache,
    AWSCredentialsProviderFactory,
)
from splunksdc.config import (  # isort: skip # pylint: disable=ungrouped-imports
    DateTimeField,
    LogLevelField,
    StanzaParser,
    StringField,
)
from splunksdc.utils import (  # isort: skip
    LogExceptions,
    LogWith,
)


logger = logging.get_module_logger()


class AWSBillingSettings:
    """Class for AWS Billling settings."""

    @classmethod
    def load(cls, config):
        """Loads AWS settings."""
        content = config.load("aws_settings", stanza="aws_billing_cur")
        parser = StanzaParser([LogLevelField("log_level", default="WARNING")])
        settings = parser.parse(content)
        return cls(settings)

    def __init__(self, settings):
        self._settings = settings

    def setup_log_level(self):
        """Sets log level."""
        set_log_level(self._settings.log_level)


class AWSBillingDataInput:
    """Class for AWS billing data input."""

    def __init__(self, stanza):
        self._kind = stanza.kind
        self._name = stanza.name
        self._args = stanza.content
        self._start_time = int(time.time())

    @property
    def name(self):
        """Returns name."""
        return self._name

    @property
    def start_time(self):
        """Returns start time."""
        return self._start_time

    @LogWith(datainput=name, start_time=start_time)
    @LogExceptions(
        logger, "Data input was interrupted by an unhandled exception.", lambda e: -1
    )
    def run(self, app, config):
        """Runs input."""
        settings = AWSBillingSettings.load(config)
        settings.setup_log_level()
        proxy = ProxySettings.load(config)
        proxy.hook_boto3_get_proxies()

        credentials = self._create_credentials(config)
        bucket = self._create_bucket()
        options = self._create_options()
        event_writer = self._create_event_writer(app)
        sourcetype = self._create_sourcetype()

        with app.open_checkpoint(self._name) as checkpoint:
            handler = AWSCostUsageReportHandler(
                checkpoint, credentials, bucket, event_writer, sourcetype, options
            )
            return handler.run(app, config)

    def _create_credentials(self, config):
        parser = StanzaParser(
            [
                StringField("aws_account", required=True),
                StringField("aws_iam_role"),
            ]
        )
        args = self._extract_arguments(parser)
        sts_endpoint_url = tacommon.get_endpoint_url(
            self._args, "sts_private_endpoint_url"
        )
        factory = AWSCredentialsProviderFactory(
            config, self._args.get("aws_s3_region"), sts_endpoint_url
        )
        provider = factory.create(args.aws_account, args.aws_iam_role)
        credentials = AWSCredentialsCache(provider)
        return credentials

    def _create_bucket(self):
        parser = StanzaParser(
            [
                StringField("bucket_name", required=True),
                StringField("bucket_region", required=True),
            ]
        )
        s3_endpoint_url = tacommon.get_endpoint_url(
            self._args, "s3_private_endpoint_url"
        )
        args = self._extract_arguments(parser)
        return S3Bucket(args.bucket_name, args.bucket_region, s3_endpoint_url)

    def _create_options(self):
        parser = StanzaParser(
            [
                StringField(
                    "report_prefix",
                    default="",  # pylint: disable=redundant-u-string-prefix
                ),
                StringField("temp_folder", default=None),
                DateTimeField("start_date", default="1970-01", fmt="%Y-%m"),
                StringField("report_names", default=r".*"),
            ]
        )
        return self._extract_arguments(parser)

    def _create_event_writer(self, app):
        stanza = self._kind + "://" + self._name
        parser = StanzaParser(
            [
                StringField("index"),
                StringField("host"),
                StringField("stanza", fillempty=stanza),
            ]
        )
        args = self._extract_arguments(parser)
        return app.create_event_writer(**vars(args))

    def _create_sourcetype(self):
        parser = StanzaParser(
            [
                StringField("sourcetype", default="aws:billing:cur"),
            ]
        )
        args = self._extract_arguments(parser)
        return args.sourcetype

    def _extract_arguments(self, parser):
        return parser.parse(self._args)


class AWSCostUsageReportJournal:
    """Class for AWS Cost Usage Report Journal."""

    def __init__(self, store):
        self._store = store

    def is_done(self, item):
        """Checks if done."""
        pair = self._store.find(item.key)
        if not pair:
            return False
        return self._compare(pair.value, item.etag)

    def mark_done(self, item):
        """Marks as done."""
        self._store.set(item.key, item.etag)

    def sweep(self):
        """Sweep method."""
        self._store.sweep()

    @staticmethod
    def _compare(a, b, encoding="ascii"):  # pylint: disable=invalid-name
        # backward compatible with ckpt created by 4.6.x
        if isinstance(a, bytes):
            a = a.decode(encoding)
        if isinstance(b, bytes):
            b = b.decode(encoding)
        a = a.strip('"')
        b = b.strip('"')
        return a == b


class BatchEventWriter:  # pylint: disable=too-many-instance-attributes
    """Class for Batch Event writer."""

    def __init__(self, writer, source, sourcetype, **kwargs):
        self._writer = writer
        self._source = source
        self._sourcetype = sourcetype
        self._cache_lines = []
        self._cache_size = 0
        self._cache_threshold = 4 * 1024 * 1024
        self._meta_keys = list(kwargs.keys())
        self._meta_values = list(kwargs.values())

    def write(self, data):
        """Writes data."""
        self._append(data)
        self._commit()

    def _append(self, line):
        self._cache_lines.append(line)
        self._cache_size += len(line)

    def _commit(self, flush=False):
        if not self._cache_size:
            return
        if self._cache_size >= self._cache_threshold or flush:
            logger.debug("Start writing events.", count=len(self._cache_lines))
            data = "\n".join(itertools.chain(self._cache_lines, [""]))
            self._writer.write_fileobj(
                data, source=self._source, sourcetype=self._sourcetype
            )
            self._cache_lines = []
            self._cache_size = 0
            logger.debug("Write events done.", volume=len(data))

    def flush(self):
        """Flush method."""
        self._commit(flush=True)


class CSVParser:
    """Class for CSV parser."""

    def __init__(self, **kwargs):
        self._meta_keys = list(kwargs.keys())
        self._meta_values = list(kwargs.values())

    def parse(self, member):
        """Yields parsed data."""
        reader = csv.reader(member)
        fields = next(reader)  # pylint: disable=stop-iteration-return
        keys = tuple(itertools.chain(fields, self._meta_keys))
        for row in reader:
            values = itertools.chain(row, self._meta_values)
            data = self._render(list(zip(keys, values)))
            yield data

    @classmethod
    def _render(cls, pairs):
        segments = []
        for key, value in pairs:
            if not value:
                continue
            # encoding the value if whitespaces or quotes were found in value.
            if re.search(r'[ "]', value):
                value = json.encoder.encode_basestring(value)
            segments.append(
                "{0}={1}".format(key, value)  # pylint: disable=consider-using-f-string
            )
        return ", ".join(segments)


def _utf8_line_decoding(fileobj):
    for line in fileobj:
        yield line.decode("utf-8")


class AWSCostUsageReportHandler:  # pylint: disable=too-many-instance-attributes
    """Class for AWS Cost Usage Report Handler."""

    _MIN_TTL = timedelta(minutes=30)

    def __init__(  # pylint: disable=too-many-arguments
        self, checkpoint, credentials, bucket, event_writer, sourcetype, options
    ):
        self._credentials = credentials
        self._bucket = bucket
        self._checkpoint = checkpoint
        self._event_writer = event_writer
        self._prefix = options.report_prefix
        self._sourcetype = sourcetype
        self._start_date = options.start_date.strftime("%Y%m")
        self._temp_folder = options.temp_folder
        self._selector = re.compile(options.report_names)
        self._archive = ArchiveFactory.create_default_instance()

    def _is_interested_report(self, name):
        if name == "/":
            return False
        return self._selector.search(name)

    def _discover_reports(self):
        logger.info("Start discovering reports.")
        prefix = self._prefix
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        bucket = self._bucket
        credentials = self._keep_credentials_alive()
        s3_bkt = bucket.client(credentials)
        folders = bucket.list_folders(s3_bkt, prefix)
        reports = [name for name in folders if self._is_interested_report(name)]
        logger.info("Discover reports done.", reports=reports)
        return reports

    def _discover_manifests(self, report, start_date):
        logger.info("Start discovering manifests.", report=report)
        date_range_pattern = re.compile(r"\d{8}-\d{8}")
        bucket = self._bucket
        credentials = self._keep_credentials_alive()
        s3_bkt = bucket.client(credentials)
        marker = report + start_date
        manifests = []
        while True:
            files = bucket.list_files(s3_bkt, report, marker)
            if not files:
                break
            marker = files[-1].key
            for item in files:
                parts = item.key.split("/")
                if not parts[-1].endswith("-Manifest.json"):
                    continue
                report_date = parts[-2]
                if not date_range_pattern.match(report_date):
                    continue
                if start_date > report_date:
                    continue
                logger.info("Manifest file is found.", key=item.key, etag=item.etag)
                manifests.append(item)
        logger.info("Discovering manifests is done.", report=report)
        return manifests

    def _get_manifest(self, manifest):
        bucket = self._bucket
        credentials = self._keep_credentials_alive()
        s3_bkt = bucket.client(credentials)
        content = BytesIO()
        bucket.fetch(s3_bkt, manifest.key, content)
        return json.load(content)

    def _ingest_report(self, manifest):
        try:
            # use epoch time as transaction id
            txid = str(int(time.time()))
            content = self._get_manifest(manifest)
            count = 0

            for key in content.get("reportKeys", []):
                bucket = self._bucket
                credentials = self._keep_credentials_alive()
                s3_bkt = bucket.client(credentials)
                with self._open_temp_file() as cache:
                    _ = bucket.transfer(s3_bkt, key, cache)
                    uri = self._make_uri(key)
                    count += self._index_report(uri, cache, txid)

            self._index_digest(manifest, content, txid, count)
            return True
        except Exception:  # pylint: disable=broad-except
            logger.exception(
                "An error occurred while ingesting report.", mainfiest=manifest.key
            )
            return False

    def _keep_credentials_alive(self):
        if self._credentials.need_retire(self._MIN_TTL):
            self._credentials.refresh()
        return self._credentials

    def _open_temp_file(self):
        return tempfile.NamedTemporaryFile(dir=self._temp_folder)

    def _make_uri(self, key):
        uri = "s3://" + self._bucket.name + "/" + key
        return uri

    def _index_report(self, uri, cache, txid):
        logger.info("Start sending events for indexing", uri=uri)
        count = 0
        for (
            member,
            uri,  # pylint: disable=redefined-argument-from-local
        ) in self._archive.open(cache, uri):
            batch = BatchEventWriter(
                self._event_writer, source=uri, sourcetype=self._sourcetype
            )
            parser = CSVParser(_txid=txid)
            lines = _utf8_line_decoding(member)
            for event in parser.parse(lines):
                batch.write(event)
                count += 1
            batch.flush()
        logger.info("Sent report for indexing done.", uri=uri, number_of_event=count)
        return count

    def _index_digest(self, header, content, txid, count):
        # ingest the digest file
        uri = self._make_uri(header.key)
        logger.info(
            "Start sending manifest for indexing",
            uri=uri,
            size=header.size,
            etag=header.etag.strip('"'),
        )
        # by default, the sourcetype of the digest file is the original sourcetype plus ":digest"
        # e.g. aws:billing:cur -> aws:billing:cur:digest
        content["lastModified"] = header.last_modified.replace(tzinfo=None).isoformat()
        content["txid"] = txid
        content["eventCount"] = count
        sourcetype = self._sourcetype + ":digest"
        data = json.dumps(content)
        self._event_writer.write_fileobj(data, source=uri, sourcetype=sourcetype)
        logger.info("Sent digest for indexing done.", uri=uri, size=len(data))

    def run(self, app, config):  # pylint: disable=unused-argument
        """Runs input."""
        start_date = self._start_date
        journal = AWSCostUsageReportJournal(self._checkpoint)
        for container in self._discover_reports():
            for manifest in self._discover_manifests(container, start_date):
                if app.is_aborted():
                    return 0
                if journal.is_done(manifest):
                    continue
                if self._ingest_report(manifest):
                    journal.mark_done(manifest)
        journal.sweep()
        return 0


def modular_input_run(app, config):
    """Runs billing modular input."""
    inputs = app.inputs()
    datainput = AWSBillingDataInput(inputs[0])
    return datainput.run(app, config)


def main():
    """Main method for billing current module."""
    arguments = {
        "aws_account": {"title": "The name of AWS account."},
        "aws_iam_role": {"title": "The name of IAM user would be assumed."},
        "aws_s3_region": {"title": "Region to use for regional endpoint"},
        "private_endpoint_enabled": {
            "title": "To enable/disable use of private endpoint"
        },
        "s3_private_endpoint_url": {
            "title": "Private endpoint url to connect with s3 service"
        },
        "sts_private_endpoint_url": {
            "title": "Private endpoint url to connect with sts service"
        },
        "bucket_name": {"title": "What is the name of bucket."},
        "bucket_region": {"title": "Where is the bucket located."},
        "report_names": {"title": "A regex pattern for selecting reports."},
        "report_prefix": {"title": "The report prefix."},
        "start_date": {"title": "Monitoring reports later than the date."},
        "temp_folder": {"title": "An alternative temp folder path."},
    }

    SimpleCollectorV1.main(
        modular_input_run,
        title="AWS Billing (Cost And Usage Report)",
        use_single_instance=False,
        arguments=arguments,
    )
