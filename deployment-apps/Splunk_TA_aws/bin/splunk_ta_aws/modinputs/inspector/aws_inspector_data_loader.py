#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
File for AWS inspector data loader.
"""
from __future__ import absolute_import

import datetime
import threading
import time
import traceback

import splunk_ta_aws.common.ta_aws_common as tacommon
import splunk_ta_aws.common.ta_aws_consts as tac
from six.moves import range
from splunksdc import log as logging
from splunktalib import state_store

logger = logging.get_module_logger()


class AWSInspectorAssessmentRunsDataLoader:  # pylint: disable=too-many-instance-attributes
    """Class for AWS Inspector Assesment Data Loader."""

    def __init__(self, config, client, account_id):
        self._cli = client
        self._state_store = state_store.get_state_store(
            config,
            config[tac.app_name],
            collection_name="aws_inspector",
            use_kv_store=config.get(tac.use_kv_store),
        )
        self._config = config
        self._completed_arns = []
        self._last_check_at = 0
        region = config[tac.region]
        data_input = config[tac.datainput]
        self._source = "{}:{}:inspector:assessmentRun".format(  # pylint: disable=consider-using-f-string
            account_id, region
        )
        self._source_type = self._config.get(tac.sourcetype, "aws::inspector")
        self._state_key = tacommon.b64encode_text(
            "assessment_runs_{}_{}".format(  # pylint: disable=consider-using-f-string
                data_input, region
            )
        )

    @property
    def _writer(self):
        return self._config[tac.event_writer]

    def run(self):
        """Run method for input"""
        self._load()
        if not self._has_completed_arn():
            self._schedule()
        while self._has_completed_arn():
            arn = self._pop_completed_arn()
            run = self._collect_run(arn)
            if run is None:
                continue
            self._index_run(run)
            self._save()

    def _schedule(self):
        end = int(time.time()) - 120
        begin = self._last_check_at
        if end - begin < 30:
            return

        arns = self._list_completed_runs_in_time_window(begin, end)
        if arns is None:
            return

        self._completed_arns.extend(arns)
        self._last_check_at = end
        self._save()

    def _index_run(self, data):
        etime = tacommon.total_seconds(data["completedAt"])
        event = self._writer.create_event(
            index=self._config.get(tac.index, "default"),
            host=self._config.get(tac.host, ""),
            source=self._source,
            sourcetype=self._source_type,
            time=etime,
            unbroken=False,
            done=False,
            events=data,
        )
        self._writer.write_events((event,))

    def _has_completed_arn(self):
        return len(self._completed_arns) > 0

    def _pop_completed_arn(self):
        return self._completed_arns.pop()

    def _collect_run(self, arn):
        response = self._cli.describe_assessment_runs(assessmentRunArns=[arn])
        if not tacommon.is_http_ok(response):
            return None
        run = response.get("assessmentRuns")[0]
        template_arn = run["assessmentTemplateArn"]
        package_arns = run["rulesPackageArns"]
        response = self._cli.describe_assessment_templates(
            assessmentTemplateArns=[template_arn]
        )
        if not tacommon.is_http_ok(response):
            return None
        template = response.get("assessmentTemplates")[0]
        response = self._cli.describe_rules_packages(rulesPackageArns=package_arns)
        if not tacommon.is_http_ok(response):
            return None
        packages = response.get("rulesPackages")
        run["assessmentTemplate"] = template
        run["rulesPackages"] = packages
        return run

    def _list_completed_runs_in_time_window(  # pylint: disable=invalid-name
        self, begin, end
    ):
        # boto3 do not accept unix timestamp on windows
        # cast to datetime by hand
        begin = datetime.datetime.utcfromtimestamp(begin)
        end = datetime.datetime.utcfromtimestamp(end)
        params = {
            "filter": {"completionTimeRange": {"beginDate": begin, "endDate": end}}
        }
        arns = []
        while True:
            response = self._cli.list_assessment_runs(**params)
            if not tacommon.is_http_ok(response):
                return None
            items = response["assessmentRunArns"]
            arns.extend(items)
            next_token = response.get("nextToken")
            if next_token is None:
                return arns
            params["nextToken"] = next_token

    def _save(self):
        self._state_store.update_state(
            self._state_key,
            {
                "last_check_at": self._last_check_at,
                "completed_arns": self._completed_arns,
            },
        )

    def _load(self):
        state = self._state_store.get_state(self._state_key)
        if state:
            self._completed_arns = state["completed_arns"]
            self._last_check_at = state["last_check_at"]


class AWSInspectorFindingsDataLoader:  # pylint: disable=too-many-instance-attributes
    """Class for AWS inspector findings data loader."""

    def __init__(self, config, client, account_id):
        # jscpd:ignore-start
        self._cli = client
        self._state_store = state_store.get_state_store(
            config,
            config[tac.app_name],
            collection_name="aws_inspector",
            use_kv_store=config.get(tac.use_kv_store),
        )
        self._config = config
        self._finding_arns = []
        # jscpd:ignore-end

        self._last_check_at = 0
        region = config[tac.region]
        data_input = config[tac.datainput]
        self._source = (
            "{}:{}:inspector:finding".format(  # pylint: disable=consider-using-f-string
                account_id, region
            )
        )
        self._source_type = self._config.get(tac.sourcetype, "aws::inspector")
        self._state_key = tacommon.b64encode_text(
            "findings_{}_{}".format(  # pylint: disable=consider-using-f-string
                data_input, region
            )
        )

    @property
    def _writer(self):
        return self._config[tac.event_writer]

    def run(self):
        """Run method for input"""
        self._load()
        if not self._has_finding_arns():
            self._schedule()
        while self._has_finding_arns():
            arns = self._pop_finding_arns()
            findings = self._collect_findings(arns)
            if findings is None:
                continue
            self._index_findings(findings)
        self._save()

    def _schedule(self):
        end = int(time.time()) - 120
        begin = self._last_check_at
        if end - begin < 30:
            return

        arns = self._list_findings_by_time_window(begin, end)
        if arns is None:
            return

        self._finding_arns.extend(arns)
        self._last_check_at = end
        self._save()

    def _index_findings(self, findings):
        # jscpd:ignore-start
        for item in findings:
            etime = tacommon.total_seconds(item["updatedAt"])
            event = self._writer.create_event(
                index=self._config.get(tac.index, "default"),
                host=self._config.get(tac.host, ""),
                source=self._source,
                sourcetype=self._source_type,
                time=etime,
                unbroken=False,
                done=False,
                events=item,
            )
            self._writer.write_events((event,))
        # jscpd:ignore-end

    def _has_finding_arns(self):
        return len(self._finding_arns) > 0

    def _pop_finding_arns(self):
        arns = []
        for _ in range(10):
            if not self._has_finding_arns():
                break
            arn = self._finding_arns.pop()
            arns.append(arn)
        return arns

    def _collect_findings(self, arns):
        response = self._cli.describe_findings(findingArns=arns)
        if not tacommon.is_http_ok(response):
            return None
        return response.get("findings")

    def _list_findings_by_time_window(self, begin, end):
        # boto3 do not accept unix timestamp on windows
        # cast to datetime by hand
        begin = datetime.datetime.utcfromtimestamp(begin)
        end = datetime.datetime.utcfromtimestamp(end)
        params = {"filter": {"creationTimeRange": {"beginDate": begin, "endDate": end}}}
        arns = []
        # jscpd:ignore-start
        while True:
            response = self._cli.list_findings(**params)
            if not tacommon.is_http_ok(response):
                return None
            items = response.get("findingArns")
            arns.extend(items)
            next_token = response.get("nextToken")
            if next_token is None:
                return arns
            params["nextToken"] = next_token
        # jscpd:ignore-end

    def _save(self):
        self._state_store.update_state(
            self._state_key,
            {"last_check_at": self._last_check_at, "finding_arns": self._finding_arns},
        )

    def _load(self):
        state = self._state_store.get_state(self._state_key)
        if state:
            self._finding_arns = state["finding_arns"]
            self._last_check_at = state["last_check_at"]


class AWSInspectorDataLoader:
    """Class for AWS inspector data loader."""

    def __init__(self, config):
        self._config = config
        self._stopped = False
        self._lock = threading.Lock()
        self._cli, self._credentials = tacommon.get_service_client(
            self._config, tac.inspector
        )

    def _do_indexing(self):
        if self._credentials.need_retire():
            self._cli, self._credentials = tacommon.get_service_client(
                self._config, tac.inspector
            )
        account_id = self._credentials.account_id
        AWSInspectorAssessmentRunsDataLoader(self._config, self._cli, account_id).run()
        AWSInspectorFindingsDataLoader(self._config, self._cli, account_id).run()

    def __call__(self):
        if self._lock.locked():
            logger.info(
                "Last round of data collecting for inspector findings"
                "region=%s, datainput=%s is not done yet",
                self._config[tac.region],
                self._config[tac.datainput],
            )
            return

        logger.info(
            "Start collecting inspector findings for region=%s, datainput=%s",
            self._config[tac.region],
            self._config[tac.datainput],
        )

        try:
            with self._lock:
                self._do_indexing()
        except Exception:  # pylint: disable=broad-except
            logger.error(
                "Failed to collect inspector findings for region=%s, "
                "datainput=%s, error=%s",
                self._config[tac.region],
                self._config[tac.datainput],
                traceback.format_exc(),
            )

        logger.info(
            "End of collecting inspector findings for region=%s, datainput=%s",
            self._config[tac.region],
            self._config[tac.datainput],
        )

    def get_interval(self):
        """Returns input polling interval."""
        return self._config[tac.polling_interval]

    def stop(self):
        """Stops the input."""
        self._stopped = True

    def stopped(self):
        """Returns if the input is stopped or not."""
        return self._stopped or self._config[tac.data_loader_mgr].stopped()

    def get_props(self):
        """Returns config."""
        return self._config
