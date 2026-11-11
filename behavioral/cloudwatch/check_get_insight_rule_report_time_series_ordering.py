"""get-insight-rule-report-time-series-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-insight-rule-report-time-series-ordering"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """Datapoints returned in a Contributor Insights rule report (GetInsightRuleReport) are
    strictly ordered ascending by timestamp, and the contributor identified in the report matches
    the real log data ingested for this rule.
    """

    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group = ctx.unique_name("/sim2real-behav/insight-rule-")
    log_stream = ctx.unique_name("stream-")
    rule_name = ctx.unique_name("sim2real-behav-insight-rule-")
    contributor_ip = "203.0.113.42"

    logs.create_log_group(logGroupName=log_group, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    rule_definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": [log_group],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "AggregateOn": "Count",
    }
    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=json.dumps(rule_definition),
        RuleState="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    def _emit_log_events() -> None:
        now_ms = int(time.time() * 1000)
        logs.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=[
                {"timestamp": now_ms, "message": json.dumps({"ip": contributor_ip, "requestBytes": 128})}
                for _ in range(3)
            ],
        )

    # A minute-aligned start one Period back, so [StartTime, EndTime) spans at least one 60 s
    # Period from the first request; a shorter span is rejected with INVALID_TIME_RANGE.
    start_time = (int(time.time()) // 60) * 60 - 60
    _emit_log_events()

    deadline = time.monotonic() + _budget_s(ctx, 150.0)
    report = None
    while time.monotonic() < deadline:
        _emit_log_events()
        time.sleep(2)
        end_time = int(time.time())
        if end_time - start_time < 60:
            continue
        try:
            # MetricDatapoints is only populated (the key is present at all) when the
            # request explicitly asks for at least one statistic via Metrics -- real
            # CloudWatch omits the MetricDatapoints key entirely from the response
            # otherwise, rather than returning an empty/timestamps-only list.
            candidate = cw.get_insight_rule_report(
                RuleName=rule_name,
                StartTime=start_time,
                EndTime=end_time,
                Period=60,
                Metrics=["UniqueContributors"],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValue" and "INVALID_TIME_RANGE" in str(e):
                continue
            raise
        if candidate["Contributors"]:
            report = candidate
            break

    if report is None:
        if _budget_spent(ctx):
            raise TimeoutError(
                "Contributor Insights data for the rule: the run budget ended first; not graded"
            )
        raise AssertionError(
            "no Contributor Insights data appeared for the rule within the poll bound "
            "(log ingestion + rule evaluation latency)"
        )

    datapoints = report["MetricDatapoints"]
    assert len(datapoints) >= 1, f"expected at least one datapoint once contributor data exists, got {datapoints!r}"
    timestamps = [dp["Timestamp"] for dp in datapoints]
    assert timestamps == sorted(timestamps), f"datapoints were not ascending by timestamp: {timestamps}"
    assert len(timestamps) == len(set(timestamps)), f"duplicate timestamps in datapoint series: {timestamps}"

    contributor_keys = {tuple(c["Keys"]) for c in report["Contributors"]}
    assert (contributor_ip,) in contributor_keys, f"expected contributor {contributor_ip} in {contributor_keys}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
