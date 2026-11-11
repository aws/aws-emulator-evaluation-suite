"""get-trace-summaries-number-keyword-filters-derive-from-the-submitted-span."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "get-trace-summaries-number-keyword-filters-derive-from-the-submitted-span"
GROUP = "trace-data-plane"
SERVICES = ["xray"]

#: Bound on trace-summary indexing lag.
_INDEX_TIMEOUT_S = 300.0
_INDEX_INTERVAL_S = 10.0

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """Number filter keywords use values from the submitted segments: http.status partitions three
    traces by response status, and responsetime/duration thresholds select only the long trace.
    The summary reports the indexed status, and a 500 status alone does not set HasFault.

    Reference: https://docs.aws.amazon.com/xray/latest/devguide/xray-console-filters.html
    """
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    now = time.time()
    marker = "n" + _hex(12)
    scope = f'annotation.probe_run = "{marker}"'

    # Three traces submitted in ONE call so they are indexed in the same instant: whatever a
    # filter excludes, it excludes while its twins are demonstrably present.
    short_span = 0.4
    long_span = 6.0
    plan = [
        ("ok", 200, short_span),
        ("clienterror", 404, short_span),
        ("slowfault", 500, long_span),
    ]
    trace_ids: dict[str, str] = {}
    docs = []
    for label, status, span in plan:
        trace_id = _new_trace_id(now)
        trace_ids[label] = trace_id
        end = now - 1.0
        docs.append(json.dumps({
            "id": _new_segment_id(),
            "name": f"sim2real-behav-xray-num-{label}-{marker}",
            "trace_id": trace_id,
            "start_time": end - span,
            "end_time": end,
            # Traces cannot be tagged, so a per-run annotation scopes every query to this run.
            "annotations": {"probe_run": marker, "probe_label": label},
            "http": {
                "request": {"method": "GET", "url": f"https://example.invalid/num/{label}"},
                "response": {"status": status},
            },
        }))
    assert len(set(trace_ids.values())) == 3, (
        f"the three probe trace ids must be distinct or the set assertions below are "
        f"meaningless: {trace_ids!r}"
    )

    put = xr.put_trace_segments(TraceSegmentDocuments=docs)
    assert put["UnprocessedTraceSegments"] == [], (
        f"all three probe segments must be accepted before any filter is judged; X-Ray "
        f"reported {put['UnprocessedTraceSegments']!r}"
    )

    mine = set(trace_ids.values())
    win_start, win_end = now - 600.0, now + 300.0

    _poll_until(
        lambda: _summary_ids(xr, scope, win_start, win_end),
        lambda ids: mine <= ids,
        timeout_s=_INDEX_TIMEOUT_S,
        interval_s=_INDEX_INTERVAL_S,
        description=(
            "all three probe traces indexed under the annotation-equality "
            "predicate, which is what makes every exclusion below an exclusion rather than a "
            "trace that had not arrived yet"
        ),
    )

    got = _summary_ids(xr, f"{scope} AND http.status = 404", win_start, win_end) & mine
    assert got == {trace_ids["clienterror"]}, (
        f"http.status = 404 must select exactly the probe trace whose segment declared "
        f"http.response.status 404 ({trace_ids['clienterror']}) out of three traces indexed in "
        f"the same instant; it selected {sorted(got)} "
        f"(200={trace_ids['ok']} 404={trace_ids['clienterror']} 500={trace_ids['slowfault']})"
    )

    got = _summary_ids(xr, f"{scope} AND http.status != 200", win_start, win_end) & mine
    assert got == {trace_ids["clienterror"], trace_ids["slowfault"]}, (
        f"http.status != 200 must select the 404 and 500 probe traces and exclude the 200 one; "
        f"expected {sorted({trace_ids['clienterror'], trace_ids['slowfault']})}, got "
        f"{sorted(got)}. An emulator that ignores FilterExpression returns all three and one "
        f"that treats every number keyword as equality returns none"
    )

    # The threshold is derived from the submitted spans rather than a literal.
    threshold = (short_span + long_span) / 2.0
    assert short_span < threshold < long_span, (
        f"the derived responsetime threshold {threshold} must lie strictly between the two "
        f"submitted spans {short_span} and {long_span}"
    )
    got = _summary_ids(xr, f"{scope} AND responsetime > {threshold}", win_start, win_end) & mine
    assert got == {trace_ids["slowfault"]}, (
        f"responsetime > {threshold} (the midpoint of the {short_span}s and {long_span}s spans "
        f"this run submitted) must select exactly the long probe trace "
        f"{trace_ids['slowfault']}; it selected {sorted(got)}. Note this answer differs from "
        f"the http.status = 404 answer, so a target cannot satisfy both by keying on one field"
    )
    got = _summary_ids(xr, f"{scope} AND responsetime < {threshold}", win_start, win_end) & mine
    assert got == {trace_ids["ok"], trace_ids["clienterror"]}, (
        f"the complementary responsetime < {threshold} must select exactly the two "
        f"{short_span}s probe traces; expected "
        f"{sorted({trace_ids['ok'], trace_ids['clienterror']})}, got {sorted(got)}"
    )

    lo = long_span - 1.0
    hi = long_span + 1.0
    expression = f"{scope} AND duration >= {lo} AND duration <= {hi}"
    got = _summary_ids(xr, expression, win_start, win_end) & mine
    assert got == {trace_ids["slowfault"]}, (
        f"a compound duration range bracketing only the {long_span}s submitted span "
        f"([{lo}, {hi}]) must select exactly {trace_ids['slowfault']}; it selected "
        f"{sorted(got)}. This leg is what proves AND composes two number predicates rather "
        f"than the last one winning"
    )

    summary = _one_summary(xr, f"{scope} AND http.status = 500", win_start, win_end,
                           trace_ids["slowfault"])
    assert summary["Http"]["HttpStatus"] == 500, (
        f"the summary's own Http.HttpStatus must be the status the http.status filter selected "
        f"on -- the filter and the projection must be reading the same indexed value; the "
        f"summary reported Http={summary.get('Http')!r}"
    )
    # HasFault comes only from the segment's `fault` boolean; the model's "500 series error" prose
    # describes what the X-Ray SDK sets, not a derivation from http.response.status.
    assert summary["HasFault"] is False, (
        f"a segment that declares http.response.status 500 but carries no explicit `fault` "
        f"member must summarise with HasFault false -- X-Ray does not infer the flag from the "
        f"status code, only from the boolean the segment sets: {summary!r}"
    )
    assert summary["ResponseTime"] > threshold, (
        f"the model documents ResponseTime as the length of time in SECONDS between the start and "
        f"end times of the root segment, so it must exceed the derived threshold {threshold} that "
        f"selected this trace: ResponseTime={summary.get('ResponseTime')!r}"
    )


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _new_trace_id(epoch_seconds: float) -> str:
    """A syntactically valid X-Ray trace id: 1-<8 hex epoch>-<24 hex>."""
    return f"1-{int(epoch_seconds):08x}-{_hex(24)}"


def _new_segment_id() -> str:
    return _hex(16)


def _utc(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that probes at least once and raises on timeout."""
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
    """Every TraceSummary for one expression and window, raising rather than truncating.

    ``Sampling=False`` makes the scan exhaustive, so exclusions are real and not sampling artefacts.
    """
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


def _one_summary(xr, expression, start_ts, end_ts, trace_id):
    matching = [s for s in _summaries(xr, expression, start_ts, end_ts)
                if s["Id"] == trace_id]
    assert len(matching) == 1, (
        f"expected exactly one TraceSummary for {trace_id} under {expression!r}, got "
        f"{len(matching)}"
    )
    return matching[0]


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Pins the account-wide trace-segment destination to `want` and returns the original.

    A switch takes minutes to go PENDING -> ACTIVE, so the restore is registered before switching.
    """
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
    original = _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"]
    ctx.on_cleanup(lambda: _restore_trace_segment_destination(xray, original, timeout_s=timeout_s))
    if original == want:
        return original
    propagate_s = 120.0
    left = ctx.time_left()
    if left is not None:
        propagate_s = max(1.0, min(propagate_s, left - 30.0))
    deadline = time.monotonic() + propagate_s
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
    """Restores the destination and waits until it is ACTIVE, so no PENDING switch is left behind."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
