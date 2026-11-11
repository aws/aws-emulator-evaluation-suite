"""get-trace-summaries-string-operators-match-the-submitted-url."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "get-trace-summaries-string-operators-match-the-submitted-url"
GROUP = "trace-data-plane"
SERVICES = ["xray"]

_INDEX_TIMEOUT_S = 300.0
_INDEX_INTERVAL_S = 10.0
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """X-Ray's string filter operators evaluate against the submitted http.request.url: CONTAINS,
    BEGINSWITH and ENDSWITH each select the documented subset of two traces sharing a URL prefix,
    and the `user CONTAINS ""` existence idiom finds only the trace that carries a user."""
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, "XRay")

    now = time.time()
    marker = "u" + _hex(12)
    scope = f'annotation.probe_run = "{marker}"'
    prefix = f"https://example.invalid/sim2real/{marker}/"
    alpha_url = prefix + "alpha"
    beta_url = prefix + "beta"
    user_value = f"sim2real-user-{marker}"

    alpha_trace = _new_trace_id(now)
    beta_trace = _new_trace_id(now)
    assert alpha_trace != beta_trace, "the two probe trace ids must differ"
    mine = {alpha_trace, beta_trace}

    def document(trace_id, url, label, user=None):
        doc = {
            "id": _new_segment_id(),
            "name": f"sim2real-behav-xray-str-{label}-{marker}",
            "trace_id": trace_id,
            "start_time": now - 2.0,
            "end_time": now - 1.0,
            # Traces cannot be tagged; the per-run annotation and name prefix are the attribution,
            # and the annotation is the scoping predicate every query below shares.
            "annotations": {"probe_run": marker, "probe_label": label},
            "http": {"request": {"method": "GET", "url": url},
                     "response": {"status": 200}},
        }
        if user is not None:
            doc["user"] = user
        return json.dumps(doc)

    put = xr.put_trace_segments(TraceSegmentDocuments=[
        document(alpha_trace, alpha_url, "alpha", user=user_value),
        document(beta_trace, beta_url, "beta"),
    ])
    assert put["UnprocessedTraceSegments"] == [], (
        f"both probe segments must be accepted before any string filter is judged; X-Ray reported "
        f"{put['UnprocessedTraceSegments']!r}"
    )

    win_start, win_end = now - 600.0, now + 300.0

    # --- positive control ----------------------------------------------------------------------
    _poll_until(
        lambda: _summary_ids(xr, scope, win_start, win_end),
        lambda ids: mine <= ids,
        timeout_s=_INDEX_TIMEOUT_S,
        interval_s=_INDEX_INTERVAL_S,
        description=(
            "both probe traces indexed under the annotation-equality predicate, "
            "which is what makes every exclusion below an exclusion rather than a trace that had "
            "not arrived yet"
        ),
    )

    # --- CONTAINS: the distinguishing middle of one URL -----------------------------------------
    got = _summary_ids(xr, f'{scope} AND http.url CONTAINS "{marker}/alpha"',
                       win_start, win_end) & mine
    assert got == {alpha_trace}, (
        f'http.url CONTAINS "{marker}/alpha" must select exactly the trace submitted with '
        f"{alpha_url!r} ({alpha_trace}) and exclude its twin submitted with {beta_url!r}; it "
        f"selected {sorted(got)}"
    )

    # --- BEGINSWITH: the shared prefix matches both ---------------------------------------------
    got = _summary_ids(xr, f'{scope} AND http.url BEGINSWITH "{prefix}"',
                       win_start, win_end) & mine
    assert got == mine, (
        f'http.url BEGINSWITH "{prefix}" must select BOTH probe traces, since both URLs share '
        f"that prefix -- this is what separates a working prefix operator from one that has "
        f"collapsed into equality; expected {sorted(mine)}, got {sorted(got)}"
    )

    # --- BEGINSWITH must be anchored, not a substring test ---------------------------------------
    # Twin control in the same instant: the anchored query above is re-run right after, so the
    # absence cannot be an indexing artefact.
    unanchored = f"sim2real/{marker}/"
    assert not prefix.startswith(unanchored), (
        f"the unanchored fragment {unanchored!r} must NOT be a prefix of {prefix!r}, or this leg "
        f"asserts nothing"
    )
    got_unanchored = _summary_ids(xr, f'{scope} AND http.url BEGINSWITH "{unanchored}"',
                                  win_start, win_end) & mine
    got_anchored = _summary_ids(xr, f'{scope} AND http.url BEGINSWITH "{prefix}"',
                                win_start, win_end) & mine
    assert got_unanchored == set(), (
        f'BEGINSWITH must be anchored at the start of the URL: {unanchored!r} appears inside both '
        f"submitted URLs but neither URL BEGINS with it, so no probe trace may match; it selected "
        f"{sorted(got_unanchored)}"
    )
    assert got_anchored == mine, (
        f"the twin control failed: the genuinely anchored prefix must still select both probe "
        f"traces in the same instant the unanchored fragment selected none; it selected "
        f"{sorted(got_anchored)}"
    )

    # --- ENDSWITH: the distinguishing tail of the other URL --------------------------------------
    got = _summary_ids(xr, f'{scope} AND http.url ENDSWITH "{marker}/beta"',
                       win_start, win_end) & mine
    assert got == {beta_trace}, (
        f'http.url ENDSWITH "{marker}/beta" must select exactly {beta_trace}; it selected '
        f"{sorted(got)}"
    )

    # --- exact equality --------------------------------------------------------------------------
    got = _summary_ids(xr, f'{scope} AND http.url = "{alpha_url}"', win_start, win_end) & mine
    assert got == {alpha_trace}, (
        f"http.url equality on the full submitted URL {alpha_url!r} must select exactly "
        f"{alpha_trace}; it selected {sorted(got)}"
    )

    # --- the `user` keyword, by value ------------------------------------------------------------
    got = _summary_ids(xr, f'{scope} AND user = "{user_value}"', win_start, win_end) & mine
    assert got == {alpha_trace}, (
        f"the user keyword is indexed from the segment document's top-level user member, so "
        f"user = {user_value!r} must select exactly the one probe trace that carried it "
        f"({alpha_trace}); it selected {sorted(got)}"
    )

    # --- the documented existence idiom ----------------------------------------------------------
    got = _summary_ids(xr, f'{scope} AND user CONTAINS ""', win_start, win_end) & mine
    assert got == {alpha_trace}, (
        f'user CONTAINS "" is the documented way to ask whether the field EXISTS at all, so it '
        f"must select the probe trace whose segment carried a user ({alpha_trace}) and exclude "
        f"the twin that carried none; it selected {sorted(got)}. A target for which every string "
        f"contains the empty string returns both, and one that cannot parse an empty operand "
        f"returns neither"
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
