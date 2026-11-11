"""deep-cloudwatch-3-cwinsightrank-sum-and-maximum-orderings-disagree."""
from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "deep-cloudwatch-3-cwinsightrank-sum-and-maximum-orderings-disagree"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]

_PERIOD_S = 60
# (host, minutes before the anchor minute, bytes per event, events in that minute)
# Maximum ranks by each contributor's largest PER-PERIOD value, not its largest event, so the
# events span four minutes: steady has the larger total, spiky the larger single-minute peak.
_PLAN = (
    [("steady", m, 20, 3) for m in range(4)]
    + [("spiky", 2, 50, 3)]
)


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
    "resource:account-singleton:cloudwatch-insight-rule-quota",
)
def run(ctx) -> None:
    """GetInsightRuleReport ranks the same data steady-first under OrderBy=Sum and spiky-first under
    OrderBy=Maximum, with per-contributor values equal to the published totals and per-period peaks.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group = ctx.unique_name("/sim2real/cwinsightrank-")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real": "cwinsightrank"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    rule = ctx.unique_name("sim2real-cwinsightrank-")
    # The rule must exist before the events are ingested: Contributor Insights analyses on arrival.
    cw.put_insight_rule(
        RuleName=rule,
        RuleState="ENABLED",
        RuleDefinition=json.dumps(
            {
                "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
                "LogGroupNames": [log_group],
                "LogFormat": "JSON",
                "Contribution": {"Keys": ["$.host"], "ValueOf": "$.bytes", "Filters": []},
                "AggregateOn": "Sum",
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cwinsightrank"}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule]))

    stream = "events"
    logs.create_log_stream(logGroupName=log_group, logStreamName=stream)

    # Anchor on the start of the PREVIOUS minute so no event lands in the future.
    anchor_s = (int(time.time()) // _PERIOD_S) * _PERIOD_S - _PERIOD_S
    events = []
    per_period = defaultdict(lambda: defaultdict(float))
    for host, minutes_back, size, count in _PLAN:
        period_start = anchor_s - minutes_back * _PERIOD_S
        for j in range(count):
            # +5 s into the minute keeps every event clear of a period boundary.
            ts_ms = (period_start + 5) * 1000 + j
            events.append((ts_ms, json.dumps({"host": host, "bytes": size})))
            per_period[host][period_start] += size
    events.sort()
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=stream,
        logEvents=[{"timestamp": t, "message": m} for t, m in events],
    )

    expected_sum = {h: sum(p.values()) for h, p in per_period.items()}
    expected_max = {h: max(p.values()) for h, p in per_period.items()}
    expected_total = sum(expected_sum.values())
    sum_leader = max(expected_sum, key=expected_sum.get)
    max_leader = max(expected_max, key=expected_max.get)
    # Guard the experiment itself: if the plan stops separating the leaders, the check is vacuous.
    assert sum_leader != max_leader, (
        f"the published plan does not separate the leaders: sum {expected_sum!r}, max {expected_max!r}"
    )

    start = datetime.fromtimestamp(anchor_s - 600, timezone.utc)
    end = datetime.fromtimestamp(anchor_s + 600, timezone.utc)

    def _report(order_by):
        return cw.get_insight_rule_report(
            RuleName=rule, StartTime=start, EndTime=end, Period=_PERIOD_S,
            OrderBy=order_by, MaxContributorCount=10,
        )

    by_sum = _poll(
        lambda: _report("Sum"),
        lambda r: sum(c["ApproximateAggregateValue"] for c in r.get("Contributors", []))
        >= expected_total,
        timeout_s=420.0,
    )
    by_max = _report("Maximum")

    sum_keys = [c["Keys"][0] for c in by_sum["Contributors"]]
    max_keys = [c["Keys"][0] for c in by_max["Contributors"]]
    assert sum_keys[0] != max_keys[0], (
        f"OrderBy=Sum and OrderBy=Maximum agree on the #1 contributor ({sum_keys[0]!r}); over this "
        f"data they must disagree. Sum order {sum_keys!r}, Maximum order {max_keys!r}"
    )
    assert sum_keys == [sum_leader, max_leader], (
        f"OrderBy=Sum ranked {sum_keys!r}, expected {[sum_leader, max_leader]!r} "
        f"from totals {expected_sum!r}"
    )
    assert max_keys == [max_leader, sum_leader], (
        f"OrderBy=Maximum ranked {max_keys!r}, expected {[max_leader, sum_leader]!r} "
        f"from per-period maxima {expected_max!r}"
    )

    got_sum = {c["Keys"][0]: c["ApproximateAggregateValue"] for c in by_sum["Contributors"]}
    assert got_sum == expected_sum, (
        f"OrderBy=Sum ApproximateAggregateValue per contributor is {got_sum!r}, expected the "
        f"arithmetic totals of the published events {expected_sum!r}"
    )
    got_max = {c["Keys"][0]: c["ApproximateAggregateValue"] for c in by_max["Contributors"]}
    assert got_max == expected_max, (
        f"OrderBy=Maximum ApproximateAggregateValue per contributor is {got_max!r}, expected each "
        f"contributor's largest per-period total {expected_max!r}"
    )

    for label, report in (("Sum", by_sum), ("Maximum", by_max)):
        assert report["AggregationStatistic"] == "Sum", (
            f"OrderBy={label} report claims AggregationStatistic "
            f"{report['AggregationStatistic']!r}; the rule aggregates on Sum"
        )
        assert report["AggregateValue"] == expected_total, (
            f"OrderBy={label} AggregateValue is {report['AggregateValue']!r}, expected the total "
            f"{expected_total!r} of every published event"
        )
        assert report["ApproximateUniqueCount"] == len(expected_sum), (
            f"OrderBy={label} ApproximateUniqueCount is {report['ApproximateUniqueCount']!r}, "
            f"expected {len(expected_sum)!r}"
        )

    steady_points = next(c for c in by_sum["Contributors"] if c["Keys"][0] == sum_leader)["Datapoints"]
    got_series = sorted(p["ApproximateValue"] for p in steady_points)
    want_series = sorted(per_period[sum_leader].values())
    assert got_series == want_series, (
        f"the {sum_leader!r} contributor's per-period datapoints are {got_series!r}, expected one "
        f"per published minute {want_series!r}"
    )


def _poll(probe, predicate, *, timeout_s=60.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
