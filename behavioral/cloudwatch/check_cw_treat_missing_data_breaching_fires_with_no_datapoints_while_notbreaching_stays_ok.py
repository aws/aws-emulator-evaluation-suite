"""cw-treat-missing-data-breaching-fires-with-no-datapoints-while-notbreaching-stays-ok."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cw-treat-missing-data-breaching-fires-with-no-datapoints-while-notbreaching-stays-ok"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#alarms-and-missing-data
@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """Over a metric that was never written, TreatMissingData alone decides the state: 'breaching'
    goes to ALARM and 'notBreaching' to OK, with StateReason naming the treatment.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#alarms-and-missing-data
    """
    cw = ctx.client("cloudwatch")
    # Deliberately never written to. Asserted below.
    namespace = ctx.unique_name("Sim2RealDepthMissingNs")
    metric = "NeverPublished"
    breaching = ctx.unique_name("sim2real-depth-tmdb-")
    not_breaching = ctx.unique_name("sim2real-depth-tmdn-")

    for name, policy in ((breaching, "breaching"), (not_breaching, "notBreaching")):
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName=metric,
            Statistic="Maximum",
            Period=60,
            EvaluationPeriods=1,
            DatapointsToAlarm=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData=policy,
            ActionsEnabled=False,
            AlarmDescription=f"sim2real depth: TreatMissingData={policy} over a never-written metric",
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    described = {"b": _describe(cw, breaching), "n": _describe(cw, not_breaching)}
    assert described["b"]["TreatMissingData"] == "breaching", (
        f"the breaching alarm reads back TreatMissingData "
        f"{described['b'].get('TreatMissingData')!r}"
    )
    assert described["n"]["TreatMissingData"] == "notBreaching", (
        f"the notBreaching alarm reads back TreatMissingData "
        f"{described['n'].get('TreatMissingData')!r}"
    )
    # The two alarms must be identical apart from the one enum, or the divergence below is not
    # attributable to the policy.
    differing = {
        k
        for k in ("Namespace", "MetricName", "Statistic", "Period", "EvaluationPeriods",
                  "DatapointsToAlarm", "Threshold", "ComparisonOperator")
        if described["b"].get(k) != described["n"].get(k)
    }
    assert not differing, (
        f"the two alarms differ in {sorted(differing)!r} as well as TreatMissingData, so any "
        f"divergence in state cannot be attributed to the missing-data policy"
    )
    # The first evaluation may land between PutMetricAlarm and this read, so each alarm reads
    # INSUFFICIENT_DATA or the state its policy settles on; the oldest history item below proves
    # the INSUFFICIENT_DATA start.
    assert described["b"]["StateValue"] in ("INSUFFICIENT_DATA", "ALARM"), (
        f"the breaching alarm started in {described['b']['StateValue']!r}, expected "
        f"INSUFFICIENT_DATA or its settled ALARM"
    )
    assert described["n"]["StateValue"] in ("INSUFFICIENT_DATA", "OK"), (
        f"the notBreaching alarm started in {described['n']['StateValue']!r}, expected "
        f"INSUFFICIENT_DATA or its settled OK"
    )

    sequences = {k: [described[k]["StateValue"]] for k in ("b", "n")}
    deadline = time.monotonic() + 210.0
    states = {}
    while True:
        current = {"b": _describe(cw, breaching), "n": _describe(cw, not_breaching)}
        states = {k: v["StateValue"] for k, v in current.items()}
        for k, v in states.items():
            if v != sequences[k][-1]:
                sequences[k].append(v)
        if "INSUFFICIENT_DATA" not in states.values():
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"one or both alarms never left INSUFFICIENT_DATA within 210s: states {states!r}, "
                f"observed sequences {sequences!r}. The evaluator did not apply TreatMissingData to "
                f"a metric with no data, which is a FAIL and deliberately not a skip"
            )
        time.sleep(15.0)

    assert states["b"] == "ALARM", (
        f"the TreatMissingData='breaching' alarm settled on {states['b']!r}, expected ALARM: a "
        f"never-written metric is entirely missing data, and 'breaching' fills every missing "
        f"datapoint as a breach. Observed sequence {sequences['b']!r}"
    )
    assert states["n"] == "OK", (
        f"the TreatMissingData='notBreaching' alarm settled on {states['n']!r}, expected OK. "
        f"Observed sequence {sequences['n']!r}"
    )
    assert states["b"] != states["n"], (
        f"both alarms settled on {states['b']!r}; the missing-data policy is being stored and "
        f"ignored rather than applied by the evaluator"
    )

    for key, name, settled in (("b", breaching, "ALARM"), ("n", not_breaching, "OK")):
        first = _first_state_update(cw, name)
        assert (first["oldState"]["stateValue"], first["newState"]["stateValue"]) == (
            "INSUFFICIENT_DATA",
            settled,
        ), (
            f"alarm {name!r}'s first StateUpdate went {first['oldState']['stateValue']!r} -> "
            f"{first['newState']['stateValue']!r}; a new alarm starts in INSUFFICIENT_DATA and its "
            f"first evaluation over no data moves it to {settled!r}. Observed sequence "
            f"{sequences[key]!r}"
        )

    reasons = {
        "b": _describe(cw, breaching).get("StateReason") or "",
        "n": _describe(cw, not_breaching).get("StateReason") or "",
    }
    assert "no datapoints were received" in reasons["b"].lower(), (
        f"the breaching alarm's StateReason must say the evaluator saw no data, got {reasons['b']!r}"
    )
    assert "[breaching]" in reasons["b"].lower(), (
        f"the StateReason must name the treatment that produced the state -- that is the part an "
        f"emulator hardcoding a state cannot report -- got {reasons['b']!r}"
    )
    assert "[breaching]" not in reasons["n"].lower(), (
        f"the notBreaching alarm's StateReason claims a breaching treatment: {reasons['n']!r}"
    )

    # The premise: nothing was ever published, so the metric must not exist. list_metrics is used
    # ONLY as a negative here -- an empty answer is what is asserted, so its well-known discovery
    # latency cannot cause a false pass or a false fail.
    listed = []
    for page in cw.get_paginator("list_metrics").paginate(Namespace=namespace):
        listed.extend(page.get("Metrics", []))
    assert listed == [], (
        f"the namespace this check never wrote to holds metrics {listed!r}; the states above would "
        f"then not be about missing data at all"
    )


def _first_state_update(cw, alarm_name):
    """The HistoryData of the alarm's oldest StateUpdate history item, polled for up to 30 s while
    the history catches up with the state."""
    deadline = time.monotonic() + 30.0
    while True:
        items = cw.describe_alarm_history(
            AlarmName=alarm_name,
            HistoryItemType="StateUpdate",
            ScanBy="TimestampAscending",
            MaxRecords=1,
        ).get("AlarmHistoryItems", [])
        if items:
            return json.loads(items[0]["HistoryData"])
        assert time.monotonic() < deadline, (
            f"alarm {alarm_name!r} has no StateUpdate history 30s after leaving INSUFFICIENT_DATA"
        )
        time.sleep(3.0)


def _describe(cw, alarm_name):
    """The metric alarm, via a paginated DescribeAlarms."""
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == alarm_name:
                return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
