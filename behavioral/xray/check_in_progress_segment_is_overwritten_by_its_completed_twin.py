"""in-progress-segment-is-overwritten-by-its-completed-twin."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "in-progress-segment-is-overwritten-by-its-completed-twin"
GROUP = "trace-data-plane"
SERVICES = ["xray"]

_TRACE_TIMEOUT_S = 180.0
_TRACE_INTERVAL_S = 5.0
#: Trace.Duration is computed by the service from the segment's own span; the tolerance covers float
#: serialisation and the service's own rounding.
_DURATION_TOLERANCE_S = 0.25

#: Number of identical consecutive reads the freeze detector demands.
_FREEZE_READS = 3


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """An in-progress segment (in_progress true, no end_time) is accepted and retrievable, and
    re-submitting the same segment id with an end_time OVERWRITES it rather than adding a second
    segment -- with Trace.Duration then derived from the completed span."""
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    now = time.time()
    trace_id = _new_trace_id(now)
    segment_id = _new_segment_id()
    marker = "p" + _hex(12)
    name = f"sim2real-behav-xray-inprogress-{marker}"
    start_time = now - 2.0
    end_time = now - 0.5
    span = end_time - start_time
    assert span > 0, f"the submitted span must be positive, got {span}"

    open_document = {
        "id": segment_id,
        "name": name,
        "trace_id": trace_id,
        "start_time": start_time,
        "in_progress": True,
        # Traces cannot be tagged, so a per-run annotation marks this trace as the check's own.
        "annotations": {"probe_run": marker, "probe_phase": "open"},
    }

    # --- leg 1: an open segment is accepted at all -------------------------------------------
    opened = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(open_document)])
    assert opened["UnprocessedTraceSegments"] == [], (
        f"a segment document specifying in_progress instead of end_time must be accepted -- the "
        f"API documents them as alternatives -- yet X-Ray reported "
        f"{opened['UnprocessedTraceSegments']!r}. A target that treats end_time as unconditionally "
        f"required rejects the whole open-segment protocol here"
    )

    # --- leg 2: it is visible, exactly once, and reads back as open --------------------------
    trace = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[trace_id]),
        lambda r: len(r["Traces"]) == 1,
        timeout_s=_TRACE_TIMEOUT_S,
        interval_s=_TRACE_INTERVAL_S,
        description=f"the in-progress trace {trace_id} retrievable through BatchGetTraces",
    )["Traces"][0]
    open_doc = _sole_document(trace, segment_id, phase="in-progress")
    assert open_doc["in_progress"] is True, (
        f"the stored in-progress document must still declare in_progress true, so a reader can "
        f"tell an open segment from a closed one: got {open_doc.get('in_progress')!r} in "
        f"{open_doc!r}"
    )
    assert "end_time" not in open_doc, (
        f"an in-progress segment must not carry an end_time the client never sent -- inventing "
        f"one would make the segment look complete: got "
        f"{open_doc.get('end_time')!r} in {open_doc!r}"
    )
    assert open_doc["annotations"]["probe_phase"] == "open", (
        f"the open document's own annotation must round-trip: got {open_doc['annotations']!r}"
    )

    # --- leg 3: reading does not advance the segment set (freeze detector) -------------------
    _assert_frozen(xr, trace_id, {segment_id}, phase="in-progress")

    # --- leg 4: the completed twin overwrites, it does not append -----------------------------
    complete_document = {
        "id": segment_id,
        "name": name,
        "trace_id": trace_id,
        "start_time": start_time,
        "end_time": end_time,
        # A second annotation present ONLY on the completed document: if the overwrite were a
        # merge that kept the old payload, or a no-op, this key would be missing below.
        "annotations": {"probe_run": marker, "probe_phase": "closed",
                        "probe_closed_only": marker},
    }
    closed = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(complete_document)])
    assert closed["UnprocessedTraceSegments"] == [], (
        f"the completed segment carrying the SAME id as the in-progress one must be accepted, "
        f"not refused as a duplicate; X-Ray reported {closed['UnprocessedTraceSegments']!r}"
    )

    closed_trace = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[trace_id]),
        lambda r: (
            len(r["Traces"]) == 1
            and any("end_time" in json.loads(s["Document"])
                    for s in r["Traces"][0]["Segments"] if s["Id"] == segment_id)
        ),
        timeout_s=_TRACE_TIMEOUT_S,
        interval_s=_TRACE_INTERVAL_S,
        description=(
            f"the completed segment {segment_id} visible in trace {trace_id} (a stored document "
            f"carrying an end_time)"
        ),
    )["Traces"][0]
    closed_doc = _sole_document(closed_trace, segment_id, phase="completed")
    assert closed_doc.get("in_progress") is not True, (
        f"once the completed segment has overwritten the in-progress one, the stored document "
        f"must no longer declare in_progress true: got {closed_doc.get('in_progress')!r}"
    )
    assert abs(float(closed_doc["end_time"]) - end_time) < 0.001, (
        f"the completed document must carry the end_time submitted with it ({end_time}), got "
        f"{closed_doc['end_time']!r}"
    )
    assert abs(float(closed_doc["start_time"]) - start_time) < 0.001, (
        f"the overwrite must not disturb the start_time both documents agreed on "
        f"({start_time}), got {closed_doc['start_time']!r}"
    )
    assert closed_doc["annotations"]["probe_phase"] == "closed", (
        f"the stored document must be the COMPLETED one, not the open one it replaced: "
        f"probe_phase reads {closed_doc['annotations'].get('probe_phase')!r}"
    )
    assert closed_doc["annotations"]["probe_closed_only"] == marker, (
        f"an annotation present only on the completed document must be present after the "
        f"overwrite, which is what distinguishes an overwrite from a no-op or a merge that kept "
        f"the earlier payload: annotations read {closed_doc['annotations']!r}"
    )

    # --- leg 5: Trace.Duration is now derived from the completed span ------------------------
    duration = closed_trace["Duration"]
    assert abs(float(duration) - span) <= _DURATION_TOLERANCE_S, (
        f"Trace.Duration must be computed from the completed segment's own span "
        f"({span:.3f}s = {end_time} - {start_time}), not echoed or left at whatever the open "
        f"segment implied; got {duration!r}"
    )

    # --- leg 6: still exactly one segment, and still frozen under reads ----------------------
    _assert_frozen(xr, trace_id, {segment_id}, phase="completed")


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _new_trace_id(epoch_seconds: float) -> str:
    return f"1-{int(epoch_seconds):08x}-{_hex(24)}"


def _new_segment_id() -> str:
    return _hex(16)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} was still not true {timeout_s:.0f}s after the segment was "
                f"accepted; last observation: {last!r}"
            )
        time.sleep(interval_s)


def _sole_document(trace, segment_id, *, phase):
    """The one stored document for `segment_id`, failing loudly on a duplicated or absent id.

    This is the assertion the whole check turns on: an implementation that APPENDS the completed
    segment instead of overwriting the in-progress one produces two entries here.
    """
    segments = trace["Segments"]
    matching = [s for s in segments if s["Id"] == segment_id]
    assert len(matching) == 1, (
        f"exactly one stored segment must bear the id {segment_id} in the {phase} phase -- two "
        f"means the completed document was APPENDED rather than overwriting the in-progress "
        f"one, zero means it was dropped; the trace held {[s['Id'] for s in segments]}"
    )
    assert len(segments) == 1, (
        f"the {phase} trace was built from exactly one submitted segment with no remote-namespace "
        f"subsegment, so X-Ray must infer nothing and the trace must hold one segment; it held "
        f"{[s['Id'] for s in segments]}"
    )
    return json.loads(matching[0]["Document"])


def _assert_frozen(xr, trace_id, expected_ids, *, phase):
    """N consecutive reads must return the identical segment set: state must not advance on a
    read, and no timing assumption is involved."""
    seen = []
    for _ in range(_FREEZE_READS):
        resp = xr.batch_get_traces(TraceIds=[trace_id])
        assert len(resp["Traces"]) == 1, (
            f"a trace that was already retrievable must stay retrievable across repeated reads "
            f"in the {phase} phase; BatchGetTraces returned {len(resp['Traces'])} traces with "
            f"UnprocessedTraceIds={resp['UnprocessedTraceIds']!r}"
        )
        seen.append(frozenset(s["Id"] for s in resp["Traces"][0]["Segments"]))
    assert set(seen) == {frozenset(expected_ids)}, (
        f"{_FREEZE_READS} consecutive BatchGetTraces reads in the {phase} phase must all return "
        f"exactly the segment ids {sorted(expected_ids)}; the reads returned "
        f"{[sorted(s) for s in seen]}. A differing set means a read mutated the trace or the "
        f"overwrite had not settled when it was first observed"
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
