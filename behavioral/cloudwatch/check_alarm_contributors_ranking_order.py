"""alarm-contributors-ranking-order."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "alarm-contributors-ranking-order"
GROUP = 'alarms'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A new Metrics Insights GROUP BY alarm has no contributors; once in ALARM,
    DescribeAlarmContributors ranks them by descending value, stably across repeat calls.
    """
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-contrib-")
    name = ctx.unique_name("sim2real-behav-cwprobe-alarm-contrib-")
    ctx.on_cleanup(lambda _n=name: cw.delete_alarms(AlarmNames=[_n]))

    query = f'SELECT MAX(Load) FROM SCHEMA("{ns}", Contributor) GROUP BY Contributor ORDER BY MAX() DESC'
    cw.put_metric_alarm(
        AlarmName=name,
        Metrics=[{"Id": "e1", "Expression": query, "Period": 60, "ReturnData": True}],
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=50.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )

    resp0 = cw.describe_alarm_contributors(AlarmName=name)
    assert resp0.get("AlarmContributors", []) == [], (
        f"a brand-new alarm should have zero contributors, got {resp0.get('AlarmContributors')}"
    )

    contributors = {"A": 90.0, "B": 80.0, "C": 70.0}
    now = datetime.datetime.utcnow()
    for label, value in contributors.items():
        cw.put_metric_data(
            Namespace=ns,
            MetricData=[
                {
                    "MetricName": "Load",
                    "Dimensions": [{"Name": "Contributor", "Value": label}],
                    "Timestamp": now,
                    "Value": value,
                }
            ],
        )

    def probe_state():
        resp = cw.describe_alarms(AlarmNames=[name])
        alarms = resp.get("MetricAlarms", [])
        return alarms[0]["StateValue"] if alarms else None

    # Metrics Insights indexing of a just-published metric can lag by minutes on real AWS.
    try:
        state = _poll_until(
            probe_state, lambda s: s == "ALARM", timeout_s=150, interval_s=10,
            description="multi-timeseries alarm reaches ALARM from published contributor data",
        )
    except AssertionError:
        raise AssertionError(
            "Metrics Insights GROUP BY query never indexed the freshly-published "
            "contributor metrics within budget (real-AWS search-index propagation "
            "lag); DescribeAlarmContributors zero-contributor behavior above was "
            "still exercised and verified.",
        )

    assert state == "ALARM", f"expected the multi-timeseries alarm to have reached ALARM, got {state!r}"

    call_a = cw.describe_alarm_contributors(AlarmName=name).get("AlarmContributors", [])
    call_b = cw.describe_alarm_contributors(AlarmName=name).get("AlarmContributors", [])
    ids_a = [c["ContributorId"] for c in call_a]
    ids_b = [c["ContributorId"] for c in call_b]
    assert ids_a == ids_b and len(ids_a) > 0, (
        f"DescribeAlarmContributors ranking must be stable across repeat calls; got {ids_a} then {ids_b}"
    )

    # Stability alone passes a fixed wrong order; ContributorAttributes echoes the "Contributor"
    # dimension, so assert the ranking matches the query's ORDER BY MAX() DESC.
    labels_a = [c["ContributorAttributes"].get("Contributor") for c in call_a]
    expected_order = [label for label, _ in sorted(contributors.items(), key=lambda kv: kv[1], reverse=True)]
    assert labels_a == expected_order, (
        f"DescribeAlarmContributors must rank contributors by descending contribution "
        f"(expected {expected_order} from published Load values {contributors}); got {labels_a}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
