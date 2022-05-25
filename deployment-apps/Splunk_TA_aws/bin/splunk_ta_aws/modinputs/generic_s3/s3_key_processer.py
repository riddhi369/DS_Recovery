#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for S3 key processor for Generic S3.
"""
from __future__ import absolute_import

import json
import re

import splunk_ta_aws.common.ta_aws_consts as tac
import splunksdc.log as logging
import splunktalib.common.util as scutil

from . import aws_s3_checkpointer as s3ckpt
from . import aws_s3_common as s3common
from . import aws_s3_consts as asc
from . import s3_key_reader as skr


def increase_error_count(
    key_store, max_retries, key, logger, bucket_name, count=1
):  # pylint: disable=too-many-arguments
    """Increases error count."""
    key_store.increase_error_count(count=count)
    if key_store.error_count() >= max_retries:
        logger.error(
            "Data collection has failed more than %s times.",
            max_retries,
            key_name=key.name,
            bucket_name=bucket_name,
        )
        key_store.delete()


class S3KeyProcesser:
    """Class for S3 key processor"""

    base_fmt = (
        """<stream><event{unbroken}>"""
        "<source>{source}</source>"
        "<sourcetype>{sourcetype}</sourcetype>"
        "<index>{index}</index>"
        "<data>{data}</data>{done}</event></stream>"
    )

    event_fmt = base_fmt.replace("{unbroken}", "").replace("{done}", "")
    unbroken_fmt = base_fmt.replace("{unbroken}", ' unbroken="1"').replace("{done}", "")
    done_fmt = base_fmt.replace("{unbroken}", ' unbroken="1"').replace(
        "{done}", "<done/>"
    )

    def __init__(
        self, s3_conn, loader_service, key_object, config, logger
    ):  # pylint: disable=too-many-arguments
        self._loader_service = loader_service
        self._config = config
        self.s3_conn = s3_conn
        self._key = key_object
        self._key_store = s3ckpt.S3KeyCheckpointer(config, self._key)
        self._logger = logger
        self._reader = None

    def __call__(self):
        with logging.LogContext(
            datainput=self._config[asc.data_input],
            bucket_name=self._config[asc.bucket_name],
            job_uid=self._config[asc.job_uid],
            start_time=self._config[asc.start_time],
            key_name=self._key.name,
            last_modified=self._key.last_modified,
            phase="fetch_key",
        ):
            try:
                self._safe_call()
            except Exception:  # pylint: disable=broad-except
                self._logger.exception("Failed to handle key.")
                increase_error_count(
                    self._key_store,
                    self._config[asc.max_retries],
                    self._key,
                    self._logger,
                    self._config[asc.bucket_name],
                )

    def _safe_call(self):
        config = {
            "s3_conn": self.s3_conn,
            asc.bucket_name: self._config[asc.bucket_name],
            asc.key_object: self._key,
            asc.key: self._key.name,
            asc.max_retries: self._config[asc.max_retries],
        }
        self._reader = skr.create_s3_key_reader(config, self._logger)

        self._logger.debug("Start processing.")

        try:
            self._do_call()
        except Exception:  # pylint: disable=broad-except
            increase_error_count(
                self._key_store,
                self._config[asc.max_retries],
                self._key,
                self._logger,
                self._config[asc.bucket_name],
            )
            self._logger.exception("Exception happened when fetching object.")
            self._reader.close(fast=True)
        self._logger.debug("End of processing.")

    def _do_call(self):
        logger = self._logger
        bucket_name, key_name = self._config[asc.bucket_name], self._key.name
        self._key_store.set_state(asc.processing)
        source = "s3://{bucket_name}/{key_name}".format(  # pylint: disable=consider-using-f-string
            bucket_name=bucket_name, key_name=key_name
        )

        if self._key_store.etag() != self._key.etag:
            logger.warning(
                "Last round of data collection was not completed,"
                " etag changed this round, start from beginning."
            )
            self._key_store.set_offset(0, commit=False)
            self._key_store.set_eof(eof=False)
        elif self._key_store.eof():
            self.set_eof()
            return

        offset = self._key_store.offset()
        if not self._key_store.eof() and offset:
            logger.info("Seeking offset for object.", offset=offset)
            self._reader.seek(offset)

        self._do_index(source)

    def _get_decoder(self):
        encoding = self._config.get(asc.character_set)
        if not encoding or encoding == "auto":
            encoding = self._key_store.encoding()

        previous_chunk = b""
        for previous_chunk in self._reader:
            break

        decoder, encoding = s3common.get_decoder(encoding, previous_chunk)
        self._key_store.set_encoding(encoding)
        return decoder, previous_chunk

    def _encode_to_utf8(self, decoder, chunk):
        if not chunk:
            return None
        try:
            data = decoder.decode(chunk)
            return scutil.escape_cdata(data)
        except Exception:  # pylint: disable=broad-except
            self._logger.exception(
                "Failed to decode data.", encoding=self._config[asc.character_set]
            )
            return None

    def _do_index(self, source):
        decoder, previous_chunk = self._get_decoder()
        chunk = previous_chunk

        total = 0
        count = 0
        for chunk in self._reader:
            if self._loader_service.stopped():
                break

            size = len(previous_chunk)
            total += size
            count += 1
            data = self._encode_to_utf8(decoder, previous_chunk)
            if data is not None:
                data = self.unbroken_fmt.format(
                    source=source,
                    sourcetype=self._config[tac.sourcetype],
                    index=self._config[tac.index],
                    data=data,
                )
                self._loader_service.write_events(data)
            previous_chunk = chunk
            if count % 100 == 0:
                self._key_store.increase_offset(total)
                self._logger.info("Indexed S3 files.", action="index", size=total)
                total = 0
        self._key_store.increase_offset(total)
        self._logger.info("Indexed S3 files.", action="index", size=total)

        if not self._loader_service.stopped():
            size = len(chunk)
            data = self._encode_to_utf8(decoder, chunk)

            if data is not None:
                if not data.endswith("\n"):
                    data += "\n"

                data = self.done_fmt.format(
                    source=source,
                    sourcetype=self._config[tac.sourcetype],
                    index=self._config[tac.index],
                    data=data,
                )
                self._loader_service.write_events(data)

            self._key_store.increase_offset(size)
            self._logger.info("Indexed S3 files.", action="index", size=size)
            self.set_eof()

    def set_eof(self):
        """Sets EOF."""
        self._key_store.set_eof(eof=True)
        self._key_store.delete()
        self._reader.close(fast=False)


class S3KeyCloudTrailProcesser(S3KeyProcesser):
    """Class for S3 key cloudtrail processor"""

    def __init__(
        self, s3_conn, loader_service, s3_key_object, config, logger
    ):  # pylint: disable=too-many-arguments, useless-super-delegation
        super(  # pylint: disable=super-with-arguments
            S3KeyCloudTrailProcesser, self
        ).__init__(s3_conn, loader_service, s3_key_object, config, logger)

    def _do_index(self, source):
        logger = self._logger
        all_data = list(self._reader)
        size = sum((len(data) for data in all_data), 0)
        if not all_data:
            self.set_eof()
            return

        try:
            all_data = json.loads(b"".join(all_data))
        except ValueError:
            logger.error("Invalid key of CloudTrail file.")
            self.set_eof()
            return

        records = all_data.get("Records", [])
        blacklist = self._config[asc.ct_blacklist]
        if blacklist:
            blacklist = re.compile(blacklist)
        else:
            blacklist = None

        loader_service = self._loader_service

        events = []
        for record in records:
            if loader_service.stopped():
                break

            if blacklist is not None and blacklist.search(record["eventName"]):
                continue

            data = self.event_fmt.format(
                source=source,
                sourcetype=self._config[tac.sourcetype],
                index=self._config[tac.index],
                data=scutil.escape_cdata(json.dumps(record)),
            )
            events.append(data)

        if events:
            logger.info(
                "Indexed cloudtrail records.",
                action="index",
                num_reocords=len(records),
                size=size,
            )
            loader_service.write_events("".join(events))

        if not loader_service.stopped():
            self._key_store.increase_offset(len(all_data))
            self.set_eof()


sourcetype_to_indexer = {
    asc.aws_s3: S3KeyProcesser,
    asc.aws_elb_accesslogs: S3KeyProcesser,
    asc.aws_cloudfront_accesslogs: S3KeyProcesser,
    asc.aws_s3_accesslogs: S3KeyProcesser,
    asc.aws_cloudtrail: S3KeyCloudTrailProcesser,
}


def create_s3_key_processer(s3_conn, config, loader_service, s3_key_object, logger):
    """Returns S3 key processor."""
    Cls = sourcetype_to_indexer.get(  # pylint: disable=invalid-name
        config[tac.sourcetype], S3KeyProcesser
    )
    return Cls(s3_conn, loader_service, s3_key_object, config, logger)
