"""put-log-events-emits-awslogs-incoming-metrics-for-the-log-group."""
from __future__ import annotations

# AWS behaviors this check relies on:
#  1. AWS/Logs IncomingLogEvents{LogGroupName} lands within 420s of PutLogEvents for a
#     log group created seconds earlier (docs say CloudWatch Logs publishes every minute;
#     the first datapoint for a brand-new group may lag longer).
#  2. IncomingLogEvents Sum over the window equals the event count EXACTLY (5), i.e. the
#     metric is not double-counted and no other writer touches a group we just created.
#  3. IncomingBytes lies in [raw_utf8_bytes, raw_utf8_bytes + 26*N]. The docs define the
#     PutLogEvents batch size as "sum of all event messages in UTF-8, plus 26 bytes for
#     each log event" but describe IncomingBytes only as "uncompressed bytes uploaded",
#     so the band deliberately admits both readings.
#  4. GetMetricStatistics reports Unit "None" for IncomingLogEvents and "Bytes" for
#     IncomingBytes (per the AWS/Logs metric table).
#  5. The LogGroupName dimension really partitions: the second group reports its own
#     count (2), not the account total.

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-log-events-emits-awslogs-incoming-metrics-for-the-log-group"
GROUP = "telemetry"
SERVICES = ["logs"]

# Documented API constant, identical and non-adjustable in every account: PutLogEvents
# sizes a batch as "the sum of all event messages in UTF-8, plus 26 bytes for each log
# event" (Smithy PutLogEvents documentation). Pinning it is correct per B10.
_EVENT_OVERHEAD_BYTES = 26

# One message is deliberately multibyte and long enough that the UTF-8 byte count exceeds
# the character count by far more than 26*N, so a target that computes IncomingBytes from
# character length falls below the accepted band instead of hiding inside it.
_PROBE_MESSAGES = [
    "sim2real-incoming-probe-alpha",
    "sim2real-incoming-probe-beta",
    "sim2real-incoming-probe-" + "日" * 200,
    "sim2real-incoming-probe-ééé",
    "sim2real-incoming-probe-omega",
]
_CONTROL_MESSAGES = [
    "sim2real-incoming-control-one",
    "sim2real-incoming-control-two",
]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents publishes AWS/Logs IncomingLogEvents and IncomingBytes for the written log group
    with the exact event count, a byte count derived from the UTF-8 message bytes, the documented
    units, and a LogGroupName dimension that really partitions per group."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    probe_group = _make_group(ctx, logs, "sim2real-behav-logs-incoming-probe-")
    control_group = _make_group(ctx, logs, "sim2real-behav-logs-incoming-control-")

    # Start the metric window a full period before the write so the minute-aligned
    # datapoint CloudWatch Logs publishes cannot fall outside it.
    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    # _write asserts internally that PutLogEvents reported no rejected events.
    _write(logs, probe_group, _PROBE_MESSAGES)
    _write(logs, control_group, _CONTROL_MESSAGES)

    probe_raw = sum(len(m.encode("utf-8")) for m in _PROBE_MESSAGES)
    probe_n = len(_PROBE_MESSAGES)
    control_n = len(_CONTROL_MESSAGES)

    # --- 1. IncomingLogEvents for the probe group: the count is exact.
    #
    # Bounded retry, not a sleep: CloudWatch Logs publishes AWS/Logs metrics once a
    # minute and CloudWatch itself needs a period to make them readable, so the wait is
    # for genuine asynchrony. The deadline raises.
    probe_dims = [{"Name": "LogGroupName", "Value": probe_group}]
    events_dps = _poll_until(
        lambda: _datapoints(cw, "IncomingLogEvents", probe_dims, window_start),
        lambda dps: bool(dps),
        timeout_s=420.0,
        interval_s=15.0,
        description=(
            f"AWS/Logs IncomingLogEvents{{LogGroupName={probe_group}}} becomes readable "
            f"after PutLogEvents of {probe_n} events"
        ),
    )
    events_sum = sum(dp["Sum"] for dp in events_dps)
    assert events_sum == float(probe_n), (
        f"expected AWS/Logs IncomingLogEvents Sum == {probe_n} (the exact number of events "
        f"written to {probe_group}, a log group this check created so nothing else writes "
        f"to it), got {events_sum} across {len(events_dps)} datapoints"
    )
    events_units = {dp["Unit"] for dp in events_dps}
    assert events_units == {"None"}, (
        f"expected IncomingLogEvents datapoints to carry Unit 'None' per the AWS/Logs "
        f"metric table, got {sorted(events_units)}"
    )

    # --- 2. IncomingBytes derives from the UTF-8 message bytes, not the character count.
    bytes_dps = _poll_until(
        lambda: _datapoints(cw, "IncomingBytes", probe_dims, window_start),
        lambda dps: bool(dps),
        timeout_s=420.0,
        interval_s=15.0,
        description=(
            f"AWS/Logs IncomingBytes{{LogGroupName={probe_group}}} becomes readable"
        ),
    )
    bytes_sum = sum(dp["Sum"] for dp in bytes_dps)
    lower = float(probe_raw)
    upper = float(probe_raw + _EVENT_OVERHEAD_BYTES * probe_n)
    assert lower <= bytes_sum <= upper, (
        f"expected AWS/Logs IncomingBytes Sum in [{lower}, {upper}] -- the sum of the "
        f"{probe_n} messages' UTF-8 byte lengths ({probe_raw}), optionally plus the "
        f"documented {_EVENT_OVERHEAD_BYTES} bytes of per-event overhead -- got {bytes_sum}; "
        f"a value near {sum(len(m) for m in _PROBE_MESSAGES)} means the target counted "
        f"characters instead of UTF-8 bytes"
    )
    bytes_units = {dp["Unit"] for dp in bytes_dps}
    assert bytes_units == {"Bytes"}, (
        f"expected IncomingBytes datapoints to carry Unit 'Bytes' per the AWS/Logs metric "
        f"table, got {sorted(bytes_units)}"
    )

    # --- 3. Freeze detector: reading the metric must not advance it. Three
    # consecutive reads over an IDENTICAL, now-closed window must return the same Sum.
    frozen_end = datetime.now(timezone.utc)
    seen = []
    for _ in range(3):
        dps = _datapoints(cw, "IncomingLogEvents", probe_dims, window_start, end=frozen_end)
        seen.append(sum(dp["Sum"] for dp in dps))
        time.sleep(2.0)
    assert len(set(seen)) == 1 and seen[0] == float(probe_n), (
        f"expected three consecutive reads of a closed window to all return "
        f"{float(probe_n)} -- GetMetricStatistics must not itself ingest log events -- got "
        f"{seen}"
    )

    # --- 4. Twin control in the same run: the LogGroupName dimension partitions. A
    # target that publishes an account-wide counter under every group name reports 7 here.
    control_dims = [{"Name": "LogGroupName", "Value": control_group}]
    control_dps = _poll_until(
        lambda: _datapoints(cw, "IncomingLogEvents", control_dims, window_start),
        lambda dps: bool(dps),
        timeout_s=420.0,
        interval_s=15.0,
        description=(
            f"AWS/Logs IncomingLogEvents{{LogGroupName={control_group}}} becomes readable "
            f"for the twin control group"
        ),
    )
    control_sum = sum(dp["Sum"] for dp in control_dps)
    assert control_sum == float(control_n), (
        f"expected the twin control group {control_group} to report exactly its own "
        f"{control_n} events, got {control_sum}; {float(probe_n + control_n)} would mean the "
        f"LogGroupName dimension is ignored and one account-wide counter is served for "
        f"every group"
    )

    # --- 5. Terminal read on the log side too, so a target that publishes plausible
    # metrics while dropping the events cannot pass: the events really are stored.
    stored = _poll_until(
        lambda: _stored_messages(logs, probe_group),
        lambda msgs: len(msgs) == probe_n,
        timeout_s=120.0,
        interval_s=5.0,
        description=f"all {probe_n} events readable back out of {probe_group}",
    )
    assert stored == sorted(_PROBE_MESSAGES), (
        f"expected the stored messages to be byte-identical to what was written "
        f"({probe_n} messages), got {len(stored)} messages differing from the input"
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


def _make_group(ctx, logs, prefix: str) -> str:
    name = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda _n=name: logs.delete_log_group(logGroupName=_n))
    return name


def _write(logs, group: str, messages: list[str]) -> int:
    """Create a stream, write every message in one batch, return the accepted count."""
    stream = f"{group}-stream"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    base = _now_ms()
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(messages)],
    )
    rejected = resp.get("rejectedLogEventsInfo")
    assert not rejected, (
        f"expected PutLogEvents to accept all {len(messages)} in-window events for {group}, "
        f"got rejectedLogEventsInfo {rejected!r}"
    )
    return len(messages)


def _datapoints(cw, metric_name: str, dimensions, start, end=None):
    resp = cw.get_metric_statistics(
        Namespace="AWS/Logs",
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=end if end is not None else datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60,
        Statistics=["Sum", "SampleCount"],
    )
    return resp["Datapoints"]


def _stored_messages(logs, group: str) -> list[str]:
    resp = logs.filter_log_events(logGroupName=group, limit=100)
    return sorted(e["message"] for e in resp["events"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
