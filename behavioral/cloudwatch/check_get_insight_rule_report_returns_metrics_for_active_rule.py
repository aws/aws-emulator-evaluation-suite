"""get-insight-rule-report-returns-metrics-for-active-rule."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-insight-rule-report-returns-metrics-for-active-rule"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """After PutInsightRule creates an active rule fed by real log events,
    GetInsightRuleReport returns a populated report for the queried time range."""
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")

    log_group = ctx.unique_name("/sim2real/insight-rule-")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    stream = ctx.unique_name("stream-")
    logs.create_log_stream(logGroupName=log_group, logStreamName=stream)

    rule_name = ctx.unique_name("sim2real-insight-rule-")
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

    described = cw.describe_insight_rules()
    matching = [r for r in described["InsightRules"] if r["Name"] == rule_name]
    assert matching and matching[0]["State"] == "ENABLED", (
        f"expected {rule_name} ENABLED in DescribeInsightRules, got {matching}"
    )

    # Contributor Insights does not retroactively scan log history: it only matches events
    # ingested after the rule is active. Emit a fresh batch of matching events on every poll
    # round, so whichever round lands after activation feeds the report, on every target.
    def _emit_events() -> None:
        now_ms = int(time.time() * 1000)
        events = [
            {"timestamp": now_ms - 1000 * (5 - i), "message": json.dumps({"ip": f"10.0.0.{i}"})}
            for i in range(5)
        ]
        logs.put_log_events(logGroupName=log_group, logStreamName=stream, logEvents=events)

    _emit_events()
    end = datetime.now(timezone.utc) + timedelta(minutes=5)
    start = end - timedelta(minutes=20)

    deadline = time.monotonic() + 220.0
    report = cw.get_insight_rule_report(RuleName=rule_name, StartTime=start, EndTime=end, Period=60)
    assert "AggregationStatistic" in report, f"GetInsightRuleReport missing AggregationStatistic: {report}"
    assert "Contributors" in report and isinstance(report["Contributors"], list), (
        f"GetInsightRuleReport Contributors schema: {report}"
    )
    while time.monotonic() < deadline and not report["Contributors"]:
        time.sleep(2)
        _emit_events()
        report = cw.get_insight_rule_report(RuleName=rule_name, StartTime=start, EndTime=end, Period=60)

    if not report["Contributors"]:
        raise AssertionError(
            "Contributor Insights ingestion did not surface contributor data for the "
            "freshly-created rule within the poll window (known ingestion latency)"
        )

    # AggregateOn="Count" reports back as the CloudWatch statistic name "SampleCount", not
    # the literal string "Count" -- confirmed against a real GetInsightRuleReport response.
    assert report["AggregationStatistic"] == "SampleCount", (
        f"expected AggregationStatistic 'SampleCount' (AggregateOn='Count'), got {report['AggregationStatistic']}"
    )
    ips_seen = {c["Keys"][0] for c in report["Contributors"]}
    assert any(ip.startswith("10.0.0.") for ip in ips_seen), ips_seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
