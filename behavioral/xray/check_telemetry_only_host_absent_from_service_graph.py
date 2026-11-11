"""telemetry-only-host-absent-from-service-graph."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "telemetry-only-host-absent-from-service-graph"
GROUP = 'trace-data-plane'
SERVICES = ['xray']

#: Ceiling for the traced service to reach the graph; a failure bound, never asserted as latency.
_GRAPH_TIMEOUT_S = 900

#: Grace after the traced service lands during which the telemetry-only host must stay absent.
_GRACE_WAIT_S = 240


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    """Generate a syntactically valid X-Ray segment ID: 16 hex chars."""
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=180, interval_s=15, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _utc(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)


def _graph_names(xr, start_ts, end_ts, max_pages=30):
    """Every name any graph node is known by -- Name and every entry of Names -- paginated."""
    names = set()
    token = None
    for _ in range(max_pages):
        kw = {"StartTime": _utc(start_ts), "EndTime": _utc(end_ts)}
        if token:
            kw["NextToken"] = token
        page = xr.get_service_graph(**kw)
        for svc in page.get("Services", []):
            if svc.get("Name"):
                names.add(svc["Name"])
            for alias in svc.get("Names") or []:
                names.add(alias)
        token = page.get("NextToken")
        if not token:
            break
    return names


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """A host that sends only PutTelemetryRecords never becomes a GetServiceGraph node (by Name or
    Names), while a host that sends PutTraceSegments in the same window does: the telemetry and
    trace pipelines are separate."""
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    now = time.time()
    traced_name = "sim2real-behav-xray-traced-" + _hex(6)
    telemetry_only_name = "sim2real-behav-xray-telonly-" + _hex(6)

    segment = {
        "id": new_segment_id(), "name": traced_name, "trace_id": new_trace_id(now),
        "start_time": now - 1.5, "end_time": now,
        "http": {"request": {"method": "GET", "url": "https://example.invalid/traced"},
                 "response": {"status": 200}},
    }
    # The traced segment goes first so the telemetry pipeline gets more time, not less.
    put = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"the traced segment must be accepted, or the positive half of this contrast is missing: "
        f"{put!r}"
    )

    telemetry = xr.put_telemetry_records(
        EC2InstanceId="i-" + _hex(17),
        Hostname=telemetry_only_name,
        ResourceARN="*",
        TelemetryRecords=[{
            "Timestamp": _utc(now),
            "SegmentsReceivedCount": 5,
            "SegmentsSentCount": 5,
            "SegmentsSpilloverCount": 0,
            "SegmentsRejectedCount": 0,
        }],
    )
    assert telemetry["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"PutTelemetryRecords must accept a well-formed record, or the absence below is trivial: "
        f"{telemetry!r}"
    )

    graph_names = _poll_until(
        lambda: _graph_names(xr, now - 600, time.time() + 300),
        lambda names: traced_name in names,
        timeout_s=_GRAPH_TIMEOUT_S,
        interval_s=15,
        description="the traced service present in the service graph",
    )
    assert traced_name in graph_names, (
        f"the traced service is absent from the graph, so the absence assertion below would be "
        f"vacuous: saw {len(graph_names)} names"
    )
    assert telemetry_only_name not in graph_names, (
        f"a host that only reported telemetry records became a service-graph node -- an emulator "
        f"conflating the telemetry and trace pipelines invents topology real X-Ray does not draw: "
        f"saw {sorted(n for n in graph_names if n.startswith('sim2real-behav-xray-'))!r}"
    )

    # Bounded grace for the telemetry pipeline; only the host appearing can fail the check.
    grace_deadline = time.monotonic() + _GRACE_WAIT_S
    checks = 0
    while time.monotonic() < grace_deadline:
        time.sleep(2)
        checks += 1
        later = _graph_names(xr, now - 600, time.time() + 300)
        assert telemetry_only_name not in later, (
            f"the telemetry-only host appeared in the service graph after {checks} further "
            f"page-throughs: saw {sorted(n for n in later if n.startswith('sim2real-behav-xray-'))!r}"
        )
        assert traced_name in later, (
            f"the traced service dropped out of the graph mid-grace, so the re-checked absence is "
            f"no longer being measured against a populated aggregate: saw {len(later)} names"
        )


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want` until cleanup; return the original.

    The destination is one setting per account and region and a switch takes minutes to settle."""
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
    # Restore is registered before the switch so a refused or unsettled switch is still undone;
    # a destination left on CloudWatchLogs makes GetTraceSummaries return nothing.
    original = _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"]
    ctx.on_cleanup(lambda: _restore_trace_segment_destination(xray, original, timeout_s=timeout_s))
    if original == want:
        return original
    deadline = time.monotonic() + 120.0
    while True:
        try:
            xray.update_trace_segment_destination(Destination=want)
            break
        except ClientError as err:
            # A just-put logs resource policy takes a while to reach X-Ray, which until then
            # refuses CloudWatchLogs naming the PutLogEvents permission it cannot yet see.
            message = err.response["Error"].get("Message", "")
            if "PutLogEvents" not in message or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    current = _settled_trace_segment_destination(xray, timeout_s=timeout_s)
    assert current["Destination"] == want, (
        f"trace-segment destination settled on {current!r} instead of {want}/ACTIVE"
    )
    return original


def _settled_trace_segment_destination(xray, *, timeout_s: float) -> dict:
    # AWS refuses UpdateTraceSegmentDestination while a previous switch is still PENDING.
    deadline = time.monotonic() + timeout_s
    while True:
        current = xray.get_trace_segment_destination()
        if current.get("Status") == "ACTIVE":
            return current
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"trace-segment destination still not ACTIVE after {timeout_s}s: {current!r}"
            )
        time.sleep(2.0)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Cleanup: put the destination back and WAIT until it reads `original`/ACTIVE, so the next
    check starts from the account state this one found rather than from a PENDING switch."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
