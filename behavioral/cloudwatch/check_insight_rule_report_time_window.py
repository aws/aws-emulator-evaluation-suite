"""insight-rule-report-time-window."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "insight-rule-report-time-window"
GROUP = 'insight-rules'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """GetInsightRuleReport aggregates only the requested window: windows entirely before or
    after a matching log event show no contributors, and a covering window eventually does."""
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    log_group = ctx.unique_name("sim2real-behav-cwprobe-insight-loggrp-")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda _n=log_group: logs.delete_log_group(logGroupName=_n))
    stream_name = ctx.unique_name("sim2real-behav-cwprobe-stream-")
    logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)

    rule_name = ctx.unique_name("sim2real-behav-cwprobe-insight-rule-")
    rule_def = json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "LogGroupNames": [log_group],
            "LogFormat": "JSON",
            "Contribution": {"Keys": ["$.requestId"], "Filters": []},
            "AggregateOn": "Count",
        }
    )
    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=rule_def,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=rule_name: cw.delete_insight_rules(RuleNames=[_n]))

    event_time = datetime.now(timezone.utc)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=stream_name,
        logEvents=[
            {"timestamp": int(event_time.timestamp() * 1000), "message": json.dumps({"requestId": "req-1"})}
        ],
    )

    period = 60

    def report(start, end):
        return cw.get_insight_rule_report(RuleName=rule_name, StartTime=start, EndTime=end, Period=period)

    before = report(event_time - timedelta(hours=2), event_time - timedelta(hours=1))
    assert before.get("ApproximateUniqueCount", 0) == 0, (
        f"expected zero contributors for a window entirely before the event, got {before}"
    )
    assert before.get("Contributors", []) == []

    after = report(event_time + timedelta(hours=1), event_time + timedelta(hours=2))
    assert after.get("ApproximateUniqueCount", 0) == 0, (
        f"expected zero contributors for a window entirely after the event, got {after}"
    )
    assert after.get("Contributors", []) == []

    # Contributor Insights processes log data for a freshly created rule with a lag of minutes.
    def probe():
        return report(event_time - timedelta(minutes=5), event_time + timedelta(minutes=5))

    try:
        covering = _poll_until(
            probe,
            lambda r: r.get("ApproximateUniqueCount", 0) > 0,
            timeout_s=220,
            interval_s=10,
            description="GetInsightRuleReport reflects the matching log event within its window",
        )
        assert covering["ApproximateUniqueCount"] > 0
        assert len(covering.get("Contributors", [])) > 0
    except AssertionError:
        raise AssertionError(
            "Contributor Insights never indexed the freshly-emitted log event within budget "
            "(real-AWS processing lag); the window-exclusion behavior (before/after windows "
            "returning zero contribution) was still exercised and verified unconditionally.",
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
