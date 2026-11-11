"""annotation-value-types-are-indexed-by-type-not-stringified."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "annotation-value-types-are-indexed-by-type-not-stringified"
GROUP = "representation"
SERVICES = ["xray"]

_INDEX_TIMEOUT_S = 300.0
_INDEX_INTERVAL_S = 10.0
_TRACE_TIMEOUT_S = 180.0
_TRACE_INTERVAL_S = 5.0
#: The two number annotation values. Chosen so that the lexicographic order of their decimal
#: spellings ("41" < "7") is the REVERSE of their numeric order (41 > 7). A target that indexes
#: annotations as strings therefore answers the comparison legs backwards rather than merely
#: returning nothing.
_HIGH = 41
_LOW = 7


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """An annotation's JSON type survives into X-Ray's index: a number is returned as
    AnnotationValue.NumberValue and compares numerically, a boolean as BooleanValue and compares
    against true/false, and the unary bracket form distinguishes set from not-set."""
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    now = time.time()
    marker = "t" + _hex(12)
    scope = f'annotation.probe_run = "{marker}"'
    high_str = "s" + _hex(8)
    low_str = "s" + _hex(8)
    assert high_str != low_str, "the two string annotation values must differ"

    # Two traces submitted in ONE call. They differ only in their annotation VALUES, and one
    # carries an extra annotation the other lacks -- that asymmetry is what the set/not-set legs
    # partition on.
    high_trace = _new_trace_id(now)
    low_trace = _new_trace_id(now)
    assert high_trace != low_trace, "the two probe trace ids must differ"
    only_high_key = "probe_only_high"

    high_annotations = {
        "probe_run": marker,
        "probe_num": _HIGH,
        "probe_flag": True,
        "probe_str": high_str,
        only_high_key: marker,
    }
    low_annotations = {
        "probe_run": marker,
        "probe_num": _LOW,
        "probe_flag": False,
        "probe_str": low_str,
    }
    high_segment_id = _new_segment_id()
    docs = [
        json.dumps({
            "id": high_segment_id,
            "name": f"sim2real-behav-xray-anntype-high-{marker}",
            "trace_id": high_trace,
            "start_time": now - 1.5,
            "end_time": now - 1.0,
            "annotations": high_annotations,
        }),
        json.dumps({
            "id": _new_segment_id(),
            "name": f"sim2real-behav-xray-anntype-low-{marker}",
            "trace_id": low_trace,
            "start_time": now - 1.5,
            "end_time": now - 1.0,
            "annotations": low_annotations,
        }),
    ]
    put = xr.put_trace_segments(TraceSegmentDocuments=docs)
    assert put["UnprocessedTraceSegments"] == [], (
        f"a segment carrying number, boolean and string annotation values must be accepted -- "
        f"the docs list all three as valid annotation types; X-Ray reported "
        f"{put['UnprocessedTraceSegments']!r}"
    )

    mine = {high_trace, low_trace}
    win_start, win_end = now - 600.0, now + 300.0

    # --- leg 1: the stored document keeps the JSON types ------------------------------------
    trace = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[high_trace]),
        lambda r: len(r["Traces"]) == 1,
        timeout_s=_TRACE_TIMEOUT_S,
        interval_s=_TRACE_INTERVAL_S,
        description=f"the number/boolean-annotated trace {high_trace} retrievable",
    )["Traces"][0]
    stored = [s for s in trace["Segments"] if s["Id"] == high_segment_id]
    assert len(stored) == 1, (
        f"exactly one stored segment must carry the submitted id {high_segment_id}; the trace "
        f"held {[s['Id'] for s in trace['Segments']]}"
    )
    doc_annotations = json.loads(stored[0]["Document"])["annotations"]
    raw_num = doc_annotations["probe_num"]
    assert not isinstance(raw_num, str), (
        f"the stored segment document must keep the number annotation as a JSON number, not a "
        f"string: probe_num came back as {raw_num!r} ({type(raw_num).__name__})"
    )
    assert float(raw_num) == float(_HIGH), (
        f"the stored number annotation must equal the submitted {_HIGH}, got {raw_num!r}"
    )
    raw_flag = doc_annotations["probe_flag"]
    assert raw_flag is True, (
        f"the stored segment document must keep the boolean annotation as a JSON boolean true, "
        f"not a string or 1: probe_flag came back as {raw_flag!r} "
        f"({type(raw_flag).__name__})"
    )
    assert doc_annotations["probe_str"] == high_str, (
        f"the stored string annotation must round-trip exactly: expected {high_str!r}, got "
        f"{doc_annotations['probe_str']!r}"
    )

    # --- leg 2: the INDEX carries the type, as the AnnotationValue union --------------------
    summaries = _poll_until(
        lambda: {s["Id"]: s for s in _summaries(xr, scope, win_start, win_end)},
        lambda by_id: mine <= set(by_id),
        timeout_s=_INDEX_TIMEOUT_S,
        interval_s=_INDEX_INTERVAL_S,
        description=(
            "both probe traces indexed under the annotation-equality predicate, "
            "which is the positive control every exclusion below depends on"
        ),
    )
    indexed = summaries[high_trace]["Annotations"]
    for key in ("probe_num", "probe_flag", "probe_str"):
        assert key in indexed, (
            f"TraceSummary.Annotations must expose the indexed annotation {key!r}; it held "
            f"{sorted(indexed)}"
        )
    num_value = _sole_annotation_value(indexed, "probe_num")
    assert set(num_value) == {"NumberValue"}, (
        f"a number annotation must be indexed through the AnnotationValue union's NumberValue "
        f"member and no other -- the union is how X-Ray reports which TYPE it indexed; "
        f"probe_num arrived as {num_value!r}"
    )
    assert float(num_value["NumberValue"]) == float(_HIGH), (
        f"NumberValue must carry the submitted number {_HIGH}, got "
        f"{num_value['NumberValue']!r}"
    )
    flag_value = _sole_annotation_value(indexed, "probe_flag")
    assert set(flag_value) == {"BooleanValue"}, (
        f"a boolean annotation must be indexed through BooleanValue and no other union member; "
        f"probe_flag arrived as {flag_value!r}"
    )
    assert flag_value["BooleanValue"] is True, (
        f"BooleanValue must carry the submitted true, got {flag_value['BooleanValue']!r}"
    )
    str_value = _sole_annotation_value(indexed, "probe_str")
    assert set(str_value) == {"StringValue"}, (
        f"a string annotation must be indexed through StringValue and no other union member; "
        f"probe_str arrived as {str_value!r}"
    )
    assert str_value["StringValue"] == high_str, (
        f"StringValue must carry the submitted {high_str!r}, got "
        f"{str_value['StringValue']!r}"
    )

    # --- leg 3/4: numeric comparison, in both directions ------------------------------------
    # The midpoint is derived from the two values this run submitted.
    midpoint = (_HIGH + _LOW) / 2.0
    assert _LOW < midpoint < _HIGH, (
        f"the derived midpoint {midpoint} must separate the two submitted number annotations "
        f"{_LOW} and {_HIGH}"
    )
    got = _summary_ids(xr, f"{scope} AND annotation.probe_num > {midpoint}",
                       win_start, win_end) & mine
    assert got == {high_trace}, (
        f"annotation.probe_num > {midpoint} must select exactly the trace annotated {_HIGH} "
        f"({high_trace}) and exclude the one annotated {_LOW}; it selected {sorted(got)}. A "
        f"target that indexed the annotation as a STRING compares {str(_HIGH)!r} against "
        f"{str(_LOW)!r} lexicographically and answers this pair backwards"
    )
    got = _summary_ids(xr, f"{scope} AND annotation.probe_num < {midpoint}",
                       win_start, win_end) & mine
    assert got == {low_trace}, (
        f"the complementary annotation.probe_num < {midpoint} must select exactly the trace "
        f"annotated {_LOW} ({low_trace}); it selected {sorted(got)}"
    )

    # --- leg 5/6: boolean comparison, in both directions ------------------------------------
    got = _summary_ids(xr, f"{scope} AND annotation.probe_flag = true",
                       win_start, win_end) & mine
    assert got == {high_trace}, (
        f"annotation.probe_flag = true must select exactly the trace annotated true "
        f"({high_trace}); it selected {sorted(got)}"
    )
    got = _summary_ids(xr, f"{scope} AND annotation.probe_flag = false",
                       win_start, win_end) & mine
    assert got == {low_trace}, (
        f"annotation.probe_flag = false must select exactly the trace annotated false "
        f"({low_trace}) -- a target that stores booleans as the strings 'true'/'false' but "
        f"compares them as truthy values collapses these two legs; it selected {sorted(got)}"
    )

    # --- leg 7/8: the unary bracket form partitions set from not-set -------------------------
    got = _summary_ids(xr, f"{scope} AND annotation[{only_high_key}]",
                       win_start, win_end) & mine
    assert got == {high_trace}, (
        f"the unary bracket form annotation[{only_high_key}] means 'this annotation is set' and "
        f"must select exactly the one probe trace that carries it ({high_trace}); it selected "
        f"{sorted(got)}"
    )
    got = _summary_ids(xr, f"{scope} AND !annotation[{only_high_key}]",
                       win_start, win_end) & mine
    assert got == {low_trace}, (
        f"the negated unary form !annotation[{only_high_key}] must select exactly the probe "
        f"trace that does NOT carry it ({low_trace}); it selected {sorted(got)}. Together with "
        f"the previous leg this partitions the two traces, so a target that answers both the "
        f"same way fails one of them"
    )


# _summaries passes Sampling=False and RAISES on unbounded pagination.


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


def _summaries(xr, expression, start_ts, end_ts, max_pages=20):
    """Every TraceSummary for one expression and window, exhaustively (Sampling=False) and with
    pagination that RAISES rather than truncating -- a truncated page one manufactures
    exclusions."""
    out = []
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
        out.extend(page["TraceSummaries"])
        token = page.get("NextToken")
        if not token:
            return out
    raise AssertionError(
        f"GetTraceSummaries still offered a NextToken after {max_pages} pages for "
        f"{expression!r}; the result set is too large for an assertion about specific probe "
        f"traces to mean anything"
    )


def _summary_ids(xr, expression, start_ts, end_ts):
    return {s["Id"] for s in _summaries(xr, expression, start_ts, end_ts)}


def _sole_annotation_value(indexed, key):
    """The one AnnotationValue X-Ray indexed for `key`, failing loudly on any other shape."""
    values = indexed[key]
    assert len(values) == 1, (
        f"exactly one annotation value was submitted for {key!r} on one segment, so the index "
        f"must report one: got {values!r}"
    )
    return values[0]["AnnotationValue"]


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want` for the rest of this check and
    return the destination it found.

    The destination (XRay, or CloudWatchLogs for Transaction Search) is ONE setting per account
    and region, shared by every X-Ray check, and a switch takes ~6 minutes to go PENDING ->
    ACTIVE. A check that leaves it on CloudWatchLogs makes GetTraceSummaries return nothing for
    every other check, so the original is read first and its restore is registered BEFORE the
    switch: a switch that is refused or never settles is still undone."""
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
