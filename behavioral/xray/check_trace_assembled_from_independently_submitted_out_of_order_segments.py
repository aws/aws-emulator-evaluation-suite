"""trace-assembled-from-independently-submitted-out-of-order-segments."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "trace-assembled-from-independently-submitted-out-of-order-segments"
GROUP = "trace-data-plane"
SERVICES = ["xray"]

_TRACE_TIMEOUT_S = 180.0
_TRACE_INTERVAL_S = 5.0
_DURATION_TOLERANCE_S = 0.25
_FREEZE_READS = 3


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """One trace assembled from three segments submitted in three separate calls, deepest first:
    a dangling parent_id is accepted, the trace is readable before its root exists, and the final
    tree reconstructs exactly the parent_id chain that was sent."""
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    now = time.time()
    marker = "s" + _hex(12)
    trace_id = _new_trace_id(now)

    root_id = _new_segment_id()
    child_id = _new_segment_id()
    grandchild_id = _new_segment_id()
    assert len({root_id, child_id, grandchild_id}) == 3, (
        f"the three segment ids must be distinct: {(root_id, child_id, grandchild_id)!r}"
    )

    # The chain this run built. Every structural assertion below is derived from THIS mapping
    # rather than from a literal, so the expected tree is generated fresh on each run.
    expected_parent = {child_id: root_id, grandchild_id: child_id}

    root_start, root_end = now - 6.0, now - 1.0
    child_start, child_end = now - 5.0, now - 2.0
    grandchild_start, grandchild_end = now - 4.0, now - 3.0
    root_span = root_end - root_start
    assert root_span > (child_end - child_start) > (grandchild_end - grandchild_start), (
        f"the three spans must nest strictly so that Duration can only be the ROOT's: "
        f"{root_span}, {child_end - child_start}, {grandchild_end - grandchild_start}"
    )

    def document(segment_id, label, start, end, parent_id=None):
        doc = {
            "id": segment_id,
            "name": f"sim2real-behav-xray-chain-{label}-{marker}",
            "trace_id": trace_id,
            "start_time": start,
            "end_time": end,
            # Traces cannot be tagged; the per-run annotation and name prefix are the attribution.
            "annotations": {"probe_run": marker, "probe_role": label},
        }
        if parent_id is not None:
            doc["parent_id"] = parent_id
        return json.dumps(doc)

    # --- call 1: the DEEPEST segment first, naming a parent that does not exist yet -----------
    first = xr.put_trace_segments(TraceSegmentDocuments=[
        document(grandchild_id, "grandchild", grandchild_start, grandchild_end,
                 parent_id=child_id)
    ])
    assert first["UnprocessedTraceSegments"] == [], (
        f"a segment whose parent_id names a segment X-Ray has never seen must be accepted -- a "
        f"callee normally reports before its caller finishes, so refusing a dangling parent_id "
        f"would break distributed tracing outright; X-Ray reported "
        f"{first['UnprocessedTraceSegments']!r}"
    )
    trace = _await_segment_ids(xr, trace_id, {grandchild_id},
                              phase="only the grandchild submitted")
    assert trace["Id"] == trace_id, (
        f"the assembled trace must be keyed by the trace_id the segment declared; got "
        f"{trace['Id']!r}"
    )

    # --- call 2: the middle segment, still naming a nonexistent root --------------------------
    second = xr.put_trace_segments(TraceSegmentDocuments=[
        document(child_id, "child", child_start, child_end, parent_id=root_id)
    ])
    assert second["UnprocessedTraceSegments"] == [], (
        f"the middle segment, submitted in its own call and naming a root that does not exist "
        f"yet, must be accepted; X-Ray reported {second['UnprocessedTraceSegments']!r}"
    )
    _await_segment_ids(xr, trace_id, {grandchild_id, child_id},
                       phase="grandchild and child submitted")

    # --- call 3: the root, last -----------------------------------------------------------------
    third = xr.put_trace_segments(TraceSegmentDocuments=[
        document(root_id, "root", root_start, root_end)
    ])
    assert third["UnprocessedTraceSegments"] == [], (
        f"the root segment must be accepted; X-Ray reported "
        f"{third['UnprocessedTraceSegments']!r}"
    )
    assembled = _await_segment_ids(xr, trace_id, {grandchild_id, child_id, root_id},
                                   phase="all three submitted")

    # --- the reassembled tree is exactly the chain that was sent ------------------------------
    # _await_segment_ids polled for EXACT set equality and raises otherwise, so by here the trace
    # holds exactly the three submitted segments and nothing X-Ray invented; re-asserting that here
    # would be an assertion that cannot fail.
    documents = {s["Id"]: json.loads(s["Document"]) for s in assembled["Segments"]}
    for doc in documents.values():
        assert doc["trace_id"] == trace_id, (
            f"every assembled segment must still declare the trace_id that joined them: "
            f"{doc!r}"
        )
        assert doc.get("inferred") is not True, (
            f"no segment here was synthesised by X-Ray, so none may be marked inferred: {doc!r}"
        )

    parentless = [sid for sid, doc in documents.items() if "parent_id" not in doc]
    assert parentless == [root_id], (
        f"exactly one segment -- the root, {root_id} -- was submitted without a parent_id, so the "
        f"assembled trace must have exactly one parentless segment; it had {sorted(parentless)}"
    )
    observed_parent = {sid: doc["parent_id"] for sid, doc in documents.items()
                       if "parent_id" in doc}
    assert observed_parent == expected_parent, (
        f"the assembled parent_id links must reconstruct the chain this run sent "
        f"({expected_parent!r}); X-Ray reported {observed_parent!r}. An implementation that "
        f"stores segments as a flat bag and drops parent_id, or that reparents everything onto "
        f"the first segment it saw, fails exactly here"
    )

    # The chain is walkable to the root in the number of hops the chain has -- derived from the
    # mapping above, not written down.
    hops = 0
    cursor = grandchild_id
    while "parent_id" in documents[cursor]:
        cursor = documents[cursor]["parent_id"]
        hops += 1
        assert hops <= len(documents), (
            f"walking parent_id from {grandchild_id} cycled without reaching a root after "
            f"{hops} hops; the links were {observed_parent!r}"
        )
    assert (cursor, hops) == (root_id, len(expected_parent)), (
        f"walking parent_id up from the deepest segment must reach the root {root_id} in exactly "
        f"{len(expected_parent)} hops; it reached {cursor!r} in {hops}"
    )

    # --- Duration comes from the root's span, not from the last segment submitted --------------
    duration = assembled["Duration"]
    assert abs(float(duration) - root_span) <= _DURATION_TOLERANCE_S, (
        f"Trace.Duration must span the whole request -- the ROOT's {root_span:.3f}s -- not the "
        f"span of whichever segment arrived last ({root_end - root_start:.3f}s root, "
        f"{child_end - child_start:.3f}s child, "
        f"{grandchild_end - grandchild_start:.3f}s grandchild); got {duration!r}"
    )

    # --- reads do not advance the assembled set -------------------------------------------------
    _assert_frozen(xr, trace_id, {root_id, child_id, grandchild_id})


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


def _segment_ids(resp):
    if len(resp["Traces"]) != 1:
        return None
    return frozenset(s["Id"] for s in resp["Traces"][0]["Segments"])


def _await_segment_ids(xr, trace_id, expected, *, phase):
    """Bounded poll until the trace holds EXACTLY `expected`. Equality, not containment: a
    superset would mean X-Ray invented a segment, which is as interesting as a missing one."""
    resp = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[trace_id]),
        lambda r: _segment_ids(r) == frozenset(expected),
        timeout_s=_TRACE_TIMEOUT_S,
        interval_s=_TRACE_INTERVAL_S,
        description=(
            f"trace {trace_id} holding exactly the segment ids {sorted(expected)} with {phase}"
        ),
    )
    return resp["Traces"][0]


def _assert_frozen(xr, trace_id, expected_ids):
    """N consecutive reads must return the identical segment set: state must not advance on a
    read, and no timing assumption is involved."""
    seen = []
    for _ in range(_FREEZE_READS):
        resp = xr.batch_get_traces(TraceIds=[trace_id])
        assert len(resp["Traces"]) == 1, (
            f"a trace that was already assembled must stay retrievable across repeated reads; "
            f"BatchGetTraces returned {len(resp['Traces'])} traces with "
            f"UnprocessedTraceIds={resp['UnprocessedTraceIds']!r}"
        )
        seen.append(frozenset(s["Id"] for s in resp["Traces"][0]["Segments"]))
    assert set(seen) == {frozenset(expected_ids)}, (
        f"{_FREEZE_READS} consecutive BatchGetTraces reads must all return exactly the segment "
        f"ids {sorted(expected_ids)}; the reads returned {[sorted(s) for s in seen]}"
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
