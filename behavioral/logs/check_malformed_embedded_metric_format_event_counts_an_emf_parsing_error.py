"""malformed-embedded-metric-format-event-counts-an-emf-parsing-error."""
from __future__ import annotations

# AWS behaviors this check relies on:
#  1. A log event whose _aws.CloudWatchMetrics is a STRING rather than a
#     list is classified as a PARSING failure and increments AWS/Logs EMFParsingErrors
#     {LogGroupName}. The neighbouring metric EMFValidationErrors covers "metric
#     definitions ... do not adhere to the ... specifications", which reads as a
#     well-formed-but-invalid body. The assertion names EMFParsingErrors only; accepting
#     either metric would make it unfalsifiable.
#  2. The latency for EMFParsingErrors to become readable (420s budget here).
#  3. PutLogEvents accepts the malformed event on the wire (no rejectedLogEventsInfo, no
#     ClientError): the EMF failure is reported ONLY through the metric, never inline.
#  4. The malformed event's intended metric name never appears in the namespace that the
#     valid control event demonstrably populates.
#  5. EMFParsingErrors datapoints carry Unit "None" per the AWS/Logs metric table.

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "malformed-embedded-metric-format-event-counts-an-emf-parsing-error"
GROUP = "telemetry"
SERVICES = ["logs"]

_DIM_NAME = "Sim2RealOp"
_DIM_VALUE = "Store"
_GOOD_METRIC = "Sim2RealGoodLatency"
_BROKEN_METRIC = "Sim2RealBrokenLatency"
_GOOD_VALUE = 42.0
_BROKEN_VALUE = 777.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Monitoring-CloudWatch-Metrics.html
@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A log event that announces itself as embedded metric format but is malformed is
    ingested and stored, produces NO metric, and is counted by CloudWatch Logs' own
    AWS/Logs EMFParsingErrors metric for that log group."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2RealEMFErr/")
    group = ctx.unique_name("sim2real-behav-logs-emferr-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = ctx.unique_name("sim2real-behav-stream-emferr-")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    marker = ctx.unique_name("emferr-marker-")
    ts = _now_ms()
    dims = [{"Name": _DIM_NAME, "Value": _DIM_VALUE}]
    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    # --- Beat 1: positive control. A well-formed EMF event in this log group and this
    # namespace must produce a metric, so the absence leg below cannot pass merely because
    # the target does no EMF extraction anywhere.
    good_body = json.dumps(
        {
            "_aws": {
                "Timestamp": ts,
                "CloudWatchMetrics": [
                    {
                        "Namespace": namespace,
                        "Dimensions": [[_DIM_NAME]],
                        "Metrics": [{"Name": _GOOD_METRIC}],
                    }
                ],
            },
            _DIM_NAME: _DIM_VALUE,
            _GOOD_METRIC: _GOOD_VALUE,
            "Marker": marker,
        },
        sort_keys=True,
    )

    # --- Beat 2: break exactly one thing. _aws is present and _aws.Timestamp is valid, so
    # the event IS identified as embedded metric format -- but CloudWatchMetrics is a
    # string where the specification requires a list, so the body cannot be parsed. This is
    # input that can never become valid, so the check has no restore step.
    broken_body = json.dumps(
        {
            "_aws": {
                "Timestamp": ts,
                "CloudWatchMetrics": (
                    f'[{{"Namespace":"{namespace}","Dimensions":[["{_DIM_NAME}"]],'
                    f'"Metrics":[{{"Name":"{_BROKEN_METRIC}"}}]}}]'
                ),
            },
            _DIM_NAME: _DIM_VALUE,
            _BROKEN_METRIC: _BROKEN_VALUE,
            "Marker": marker,
        },
        sort_keys=True,
    )

    written_at = time.monotonic()
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": ts, "message": good_body},
            {"timestamp": ts + 1, "message": broken_body},
        ],
    )
    rejected = resp.get("rejectedLogEventsInfo")
    assert not rejected, (
        "expected PutLogEvents to accept a malformed EMF body on the wire -- an EMF "
        "problem is reported only through AWS/Logs metrics, never as an inline rejection; "
        f"got rejectedLogEventsInfo {rejected!r}"
    )

    good = _poll_until(
        lambda: _stats(cw, namespace, _GOOD_METRIC, dims, window_start),
        lambda dps: bool(dps),
        timeout_s=420.0,
        interval_s=15.0,
        description=(
            f"positive control: the well-formed EMF event populates "
            f"{namespace}/{_GOOD_METRIC}"
        ),
    )
    latency_s = time.monotonic() - written_at
    good_maxima = {dp["Maximum"] for dp in good}
    assert good_maxima == {_GOOD_VALUE}, (
        f"expected the control metric's samples to all equal {_GOOD_VALUE}, got "
        f"{sorted(good_maxima)}"
    )

    # --- Beat 3: the SPECIFIC failure signal. CloudWatch Logs counts the malformed event
    # in its own AWS/Logs namespace, dimensioned by log group.
    err_dims = [{"Name": "LogGroupName", "Value": group}]
    errors = _poll_until(
        lambda: _stats(cw, "AWS/Logs", "EMFParsingErrors", err_dims, window_start),
        lambda dps: bool(dps) and sum(d["Sum"] for d in dps) >= 1.0,
        timeout_s=420.0,
        interval_s=15.0,
        description=(
            f"AWS/Logs EMFParsingErrors{{LogGroupName={group}}} reaches Sum >= 1 after a "
            f"malformed EMF event -- this is the signal that separates 'the target parsed "
            f"it and refused' from 'the target never looked at it'"
        ),
    )
    err_sum = sum(dp["Sum"] for dp in errors)
    assert err_sum >= 1.0, (
        f"expected AWS/Logs EMFParsingErrors Sum >= 1 for {group}, got {err_sum}"
    )
    err_units = {dp["Unit"] for dp in errors}
    assert err_units == {"None"}, (
        f"expected EMFParsingErrors datapoints to carry Unit 'None' per the AWS/Logs "
        f"metric table, got {sorted(err_units)}"
    )

    # --- Beat 4: effect absent, in a namespace the control just proved is live, held for a
    # window bounded by the control's own measured latency rather than a fixed sleep.
    hold_s = min(max(3.0 * latency_s, 60.0), 300.0)
    deadline = time.monotonic() + hold_s
    while True:
        broken = _stats(cw, namespace, _BROKEN_METRIC, dims, window_start)
        assert not broken, (
            f"expected NO datapoints for {_BROKEN_METRIC}: its declaration was inside a "
            f"malformed _aws block, so no metric may be published -- yet {namespace} is "
            f"demonstrably live (the control metric landed there {latency_s:.0f}s after the "
            f"write); got {broken!r}"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(10.0)

    # --- Beat 5: the event itself is stored verbatim. A failed extraction must not drop
    # the log line -- that would lose the very data the operator is looking at.
    stored = _poll_until(
        lambda: _stored_messages(logs, group, marker),
        lambda msgs: len(msgs) == 2,
        timeout_s=120.0,
        interval_s=5.0,
        description="both the valid and the malformed EMF event readable via FilterLogEvents",
    )
    assert stored == sorted([good_body, broken_body]), (
        "expected the malformed EMF event stored byte-identically alongside the valid one; "
        f"got {len(stored)} messages, first divergence "
        f"{_first_divergence(stored, sorted([good_body, broken_body]))}"
    )


# ===== helpers =====
def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stats(cw, namespace, metric_name, dimensions, start):
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60,
        Statistics=["Sum", "SampleCount", "Minimum", "Maximum"],
    )
    return resp["Datapoints"]


def _stored_messages(logs, group: str, marker: str) -> list[str]:
    resp = logs.filter_log_events(logGroupName=group, filterPattern=f'"{marker}"', limit=50)
    return sorted(e["message"] for e in resp["events"])


def _first_divergence(got: list[str], want: list[str]) -> str:
    for g, w in zip(got, want):
        if g != w:
            return f"{g[:80]!r} != {w[:80]!r}"
    return f"length {len(got)} != {len(want)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
