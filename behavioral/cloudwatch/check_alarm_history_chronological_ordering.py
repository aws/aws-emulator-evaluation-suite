"""alarm-history-chronological-ordering."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-history-chronological-ordering"
GROUP = 'alarms'
SERVICES = ['cloudwatch']

_NAMESPACE = "SimParityProbe/Behavioral"


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


@tags("axis:happy-path", "cap:c2", "concern:metrics", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmHistory with ScanBy=TimestampDescending lists StateUpdate items newest first:
    after each marked SetAlarmState the newest marked item is that transition, the marked items
    end in reverse call order, and a bogus NextToken is refused with InvalidNextToken."""
    cw = ctx.client("cloudwatch")
    # The alarm has no data, so its actual state is INSUFFICIENT_DATA and CloudWatch may return it
    # there between calls; every driven state differs from that, so each call is a transition.
    sequence = ["ALARM", "OK", "ALARM", "OK"]
    reasons = [f"seq-marker-{i}" for i in range(len(sequence))]
    name = ctx.unique_name("sim2real-behav-cwprobe-alarm-hist-")
    ctx.on_cleanup(lambda _n=name: cw.delete_alarms(AlarmNames=[_n]))
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=_NAMESPACE,
        MetricName="QueueDepth",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def probe():
        resp = cw.describe_alarm_history(
            AlarmName=name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending", MaxRecords=50
        )
        return resp.get("AlarmHistoryItems", [])

    def reason_of(item):
        return json.loads(item["HistoryData"])["newState"]["stateReason"]

    def marked(items):
        # SetAlarmState: "Metric alarms returns to their actual state quickly, often within
        # seconds", which logs CloudWatch's own StateUpdate items; only the driven ones carry a marker.
        return [it for it in items if reason_of(it) in reasons]

    seen = 0
    for state, reason in zip(sequence, reasons):
        cw.set_alarm_state(AlarmName=name, StateValue=state, StateReason=reason)
        seen += 1
        items = _poll_until(
            probe, lambda items, want=seen: len(marked(items)) >= want,
            timeout_s=30, interval_s=2, description=f"history reflects {seen} transition(s)",
        )
        newest_reason = reason_of(marked(items)[0])
        assert newest_reason == reason, (
            f"newest DescribeAlarmHistory item after transition #{seen} should be {reason!r}, "
            f"got {newest_reason!r} -- new items must be prepended, not appended"
        )

    items = probe()
    timestamps = [it["Timestamp"] for it in items]
    assert timestamps == sorted(timestamps, reverse=True), (
        f"DescribeAlarmHistory items must be in non-increasing timestamp order, got {timestamps}"
    )

    observed_reasons = [reason_of(it) for it in marked(items)]
    assert observed_reasons == list(reversed(reasons)), (
        f"expected reverse-chronological reasons {list(reversed(reasons))}, got {observed_reasons}"
    )

    # Overly-permissive check: a syntactically well-formed but bogus pagination
    # token must be rejected with InvalidNextToken, not silently treated as "no
    # token" (which would return page 1 again) or accepted as valid.
    bogus_token_code, bogus_token_message = _err(
        lambda: cw.describe_alarm_history(AlarmName=name, NextToken="not-a-real-token")
    )
    assert bogus_token_code == "InvalidNextToken", (
        f"expected InvalidNextToken for a garbage pagination token, got {bogus_token_code!r}"
    )
    expected = "Invalid NextToken : not-a-real-token"
    assert bogus_token_message == expected, (
        f"expected message {expected!r} for a garbage pagination token, got {bogus_token_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
