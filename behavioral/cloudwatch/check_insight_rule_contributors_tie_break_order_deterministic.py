"""insight-rule-contributors-tie-break-order-deterministic."""
from __future__ import annotations

import json
import math
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "insight-rule-contributors-tie-break-order-deterministic"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """When several Contributor Insights contributors have identical aggregate
    values (a genuine tie), GetInsightRuleReport orders them deterministically
    across repeated calls rather than shuffling the tie-break order."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group_name = ctx.unique_name("/sim2real/cw-insight-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    rule_name = ctx.unique_name("sim2real-cw-insight-rule-")
    rule_definition = json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "LogGroupNames": [log_group_name],
            "LogFormat": "JSON",
            "Contribution": {"Keys": ["$.user"], "Filters": []},
            "AggregateOn": "Count",
        }
    )
    # The rule must exist (and be enabled) *before* the matching log events are
    # ingested -- Contributor Insights only analyzes events as they arrive.
    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=rule_definition,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    users = [f"user-{i}" for i in range(6)]
    log_stream_name = ctx.unique_name("stream-")
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
    now_ms = int(time.time() * 1000)
    # Each user appears exactly once -> every contributor ties at aggregate value 1.
    logs.put_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        logEvents=[
            {"timestamp": now_ms, "message": json.dumps({"user": u})} for u in users
        ],
    )

    start_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    end_time = datetime.now(timezone.utc) + timedelta(minutes=10)

    def _probe():
        return cw.get_insight_rule_report(
            RuleName=rule_name,
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            MaxContributorCount=20,
        )

    def _all_contributors_present(resp):
        contributors = resp.get("Contributors", [])
        return len(contributors) >= len(users)

    first = _poll_until(_probe, _all_contributors_present, timeout_s=300.0, interval_s=10.0)
    first_contributors = first["Contributors"]

    # Sanity check this really is a tie: every contributor has the same aggregate value.
    values = {c["ApproximateAggregateValue"] for c in first_contributors}
    assert len(values) == 1 and math.isclose(next(iter(values)), 1.0), (
        f"expected all contributors tied at value 1.0, got {values}"
    )

    second = cw.get_insight_rule_report(
        RuleName=rule_name,
        StartTime=start_time,
        EndTime=end_time,
        Period=300,
        MaxContributorCount=20,
    )
    second_contributors = second["Contributors"]

    first_keys = [c["Keys"] for c in first_contributors]
    second_keys = [c["Keys"] for c in second_contributors]
    assert first_keys == second_keys, (
        f"tied contributor order was not deterministic across repeated calls: "
        f"{first_keys} vs {second_keys}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
