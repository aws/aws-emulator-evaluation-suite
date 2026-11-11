"""service-and-edge-filter-keywords-select-by-submitted-topology."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "service-and-edge-filter-keywords-select-by-submitted-topology"
GROUP = "trace-data-plane"
SERVICES = ["xray"]

_INDEX_TIMEOUT_S = 300.0
_INDEX_INTERVAL_S = 10.0
#: Topology-aware filtering can lag behind service-graph aggregation; budgeted generously
#: and bounded so an unmet condition reports as an
#: assertion about the filter rather than a claim that X-Ray was slow.
_TOPOLOGY_TIMEOUT_S = 420.0
_TOPOLOGY_INTERVAL_S = 15.0
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """Two traces sharing one root but calling different downstreams: service() and edge() select
    by the topology the segments describe, not by name matching anywhere in the trace."""
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    now = time.time()
    marker = "e" + _hex(12)
    scope = f'annotation.probe_run = "{marker}"'
    root_name = f"sim2real-behav-xray-root-{marker}"
    left_callee = f"sim2real-behav-xray-left-{marker}"
    right_callee = f"sim2real-behav-xray-right-{marker}"
    assert len({root_name, left_callee, right_callee}) == 3, "the three node names must differ"

    left_trace = _new_trace_id(now)
    right_trace = _new_trace_id(now)
    assert left_trace != right_trace, "the two probe trace ids must differ"
    mine = {left_trace, right_trace}

    def document(trace_id, callee_name, label):
        segment_id = _new_segment_id()
        return json.dumps({
            "id": segment_id,
            "name": root_name,
            "trace_id": trace_id,
            "start_time": now - 2.0,
            "end_time": now - 1.0,
            # Traces cannot be tagged; the per-run annotation and name prefixes are the
            # attribution, and the annotation is the scoping predicate every query shares.
            "annotations": {"probe_run": marker, "probe_side": label},
            "http": {"request": {"method": "GET",
                                 "url": f"https://example.invalid/topology/{label}"},
                     "response": {"status": 200}},
            # namespace "remote" is what makes X-Ray infer a downstream NODE for this subsegment;
            # that inferred node is the only thing the two traces differ by.
            "subsegments": [{
                "id": _new_segment_id(),
                "name": callee_name,
                "namespace": "remote",
                "parent_id": segment_id,
                "start_time": now - 1.8,
                "end_time": now - 1.2,
            }],
        })

    put = xr.put_trace_segments(TraceSegmentDocuments=[
        document(left_trace, left_callee, "left"),
        document(right_trace, right_callee, "right"),
    ])
    assert put["UnprocessedTraceSegments"] == [], (
        f"both probe segments, each carrying one remote-namespace subsegment, must be accepted; "
        f"X-Ray reported {put['UnprocessedTraceSegments']!r}"
    )

    win_start, win_end = now - 600.0, now + 300.0

    _poll_until(
        lambda: _summary_ids(xr, scope, win_start, win_end),
        lambda ids: mine <= ids,
        timeout_s=_INDEX_TIMEOUT_S,
        interval_s=_INDEX_INTERVAL_S,
        description=(
            "both probe traces indexed under the annotation-equality predicate, which is what "
            "makes every topology exclusion below an exclusion rather than a trace that had not "
            "arrived yet"
        ),
    )

    # --- service() names the INFERRED downstream node ------------------------------------------
    left_expression = f'{scope} AND service("{left_callee}")'
    got = _poll_until(
        lambda: _summary_ids(xr, left_expression, win_start, win_end) & mine,
        lambda ids: left_trace in ids,
        timeout_s=_TOPOLOGY_TIMEOUT_S,
        interval_s=_TOPOLOGY_INTERVAL_S,
        description=(
            f"service({left_callee!r}) selecting the probe trace whose remote subsegment named "
            f"that downstream"
        ),
    )
    assert got == {left_trace}, (
        f"service({left_callee!r}) must select exactly the trace whose remote-namespace "
        f"subsegment named that downstream ({left_trace}) and exclude its twin, which called "
        f"{right_callee!r} instead; it selected {sorted(got)}"
    )

    got = _summary_ids(xr, f'{scope} AND service("{right_callee}")', win_start, win_end) & mine
    assert got == {right_trace}, (
        f"the complementary service({right_callee!r}) must select exactly {right_trace}; it "
        f"selected {sorted(got)}. A target that treats service() as a no-op returns both and one "
        f"that cannot parse it returns neither"
    )

    # --- the shared root is matched by both -----------------------------------------------------
    got = _summary_ids(xr, f'{scope} AND service("{root_name}")', win_start, win_end) & mine
    assert got == mine, (
        f"both probe traces were submitted under the SAME root service name {root_name!r}, so "
        f"service() on it must return both -- this is what separates a working keyword from a "
        f"per-trace lookup; expected {sorted(mine)}, got {sorted(got)}"
    )

    # --- edge() names a directed connection, not a node ------------------------------------------
    left_edge = f'{scope} AND edge("{root_name}", "{left_callee}")'
    got = _poll_until(
        lambda: _summary_ids(xr, left_edge, win_start, win_end) & mine,
        lambda ids: left_trace in ids,
        timeout_s=_TOPOLOGY_TIMEOUT_S,
        interval_s=_TOPOLOGY_INTERVAL_S,
        description=(
            f"edge({root_name!r}, {left_callee!r}) selecting the trace that recorded that call"
        ),
    )
    assert got == {left_trace}, (
        f"edge({root_name!r}, {left_callee!r}) must select exactly the trace that recorded that "
        f"connection ({left_trace}); it selected {sorted(got)}"
    )
    got = _summary_ids(xr, f'{scope} AND edge("{root_name}", "{right_callee}")',
                       win_start, win_end) & mine
    assert got == {right_trace}, (
        f"edge({root_name!r}, {right_callee!r}) must select exactly {right_trace}; it selected "
        f"{sorted(got)}. Both traces share the source node, so a target that reduces edge() to "
        f"'the source appears in this trace' returns both here"
    )

    # --- the reversed edge exists in neither trace ------------------------------------------------
    # Twin control in the same instant: the forward edge query above is re-run immediately after,
    # so the absence cannot be an indexing artefact.
    reversed_ids = _summary_ids(xr, f'{scope} AND edge("{left_callee}", "{root_name}")',
                                win_start, win_end) & mine
    forward_ids = _summary_ids(xr, left_edge, win_start, win_end) & mine
    assert reversed_ids == set(), (
        f"the subsegment recorded a call FROM {root_name!r} TO {left_callee!r}, so the reversed "
        f"edge must match no probe trace -- an edge is directed; it selected "
        f"{sorted(reversed_ids)}"
    )
    assert forward_ids == {left_trace}, (
        f"the twin control failed: the forward edge must still select {left_trace} in the same "
        f"instant the reversed edge selected nothing, or the absence above is about indexing "
        f"rather than about direction; it selected {sorted(forward_ids)}"
    )

    # --- negation partitions the pair --------------------------------------------------------------
    got = _summary_ids(xr, f'{scope} AND !service("{left_callee}")', win_start, win_end) & mine
    assert got == {right_trace}, (
        f"!service({left_callee!r}) must exclude the trace that DID call it and keep its twin, so "
        f"the negation partitions the pair against the service() leg above; expected "
        f"{sorted({right_trace})}, got {sorted(got)}"
    )


# _summary_ids passes Sampling=False and paginates, RAISING rather than truncating.


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _new_trace_id(epoch_seconds: float) -> str:
    return f"1-{int(epoch_seconds):08x}-{_hex(24)}"


def _new_segment_id() -> str:
    return _hex(16)


def _utc(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} was still not true {timeout_s:.0f}s after the probe segments "
                f"were accepted; last observation: {last!r}"
            )
        time.sleep(interval_s)


def _summary_ids(xr, expression, start_ts, end_ts, max_pages=20):
    """Every trace id GetTraceSummaries reports for one expression and window.

    ``Sampling=False`` makes the scan exhaustive rather than a statistically sampled subset;
    pagination RAISES rather than truncating, because a silently truncated page one would
    manufacture the exclusions this check is built on.
    """
    ids = set()
    token = None
    for _ in range(max_pages):
        kw = {
            "StartTime": _utc(start_ts),
            "EndTime": _utc(end_ts),
            "FilterExpression": expression,
            "Sampling": False,
        }
        if token:
            kw["NextToken"] = token
        page = xr.get_trace_summaries(**kw)
        ids.update(s["Id"] for s in page["TraceSummaries"])
        token = page.get("NextToken")
        if not token:
            return ids
    raise AssertionError(
        f"GetTraceSummaries still offered a NextToken after {max_pages} pages for "
        f"{expression!r}; the result set is too large for an assertion about specific probe "
        f"traces to mean anything"
    )


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want` for the rest of this check and
    return the destination it found.

    The destination (XRay, or CloudWatchLogs for Transaction Search) is one setting per account
    and region, and a switch takes about 6 minutes to go PENDING -> ACTIVE. The original is read
    first and its restore registered before the switch, so a refused or unsettled switch is undone."""
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
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
