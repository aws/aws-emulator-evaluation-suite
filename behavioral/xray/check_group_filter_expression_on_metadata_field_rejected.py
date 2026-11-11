"""group-filter-expression-on-metadata-field-rejected."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "group-filter-expression-on-metadata-field-rejected"
GROUP = 'overly-permissive'
SERVICES = ['xray']

ERR_INVALID_REQUEST = "InvalidRequestException"
#: The parser's verbatim complaint, identical on both surfaces: `metadata` is not a token in
#: X-Ray's filter-expression language at all, so it fails at position 1 rather than as an unknown
#: field. Asserted exactly because the position is the evidence for that reading.
MSG_UNKNOWN_SYMBOL = "Error Location: line 1, position 1 : Invalid input symbol: 'met'"

_FILTER_TIMEOUT_S = 300


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    """Generate a syntactically valid X-Ray segment ID: 16 hex chars."""
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=180, interval_s=5, description="condition"):
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


def _selected_ids(xr, start_ts, end_ts, expression=None, max_pages=25):
    """Every trace id GetTraceSummaries reports, optionally filtered; paginated because the
    unfiltered result is account-wide."""
    ids = set()
    token = None
    for _ in range(max_pages):
        kw = {"StartTime": _utc(start_ts), "EndTime": _utc(end_ts)}
        if expression:
            kw["FilterExpression"] = expression
        if token:
            kw["NextToken"] = token
        page = xr.get_trace_summaries(**kw)
        ids.update(s["Id"] for s in page.get("TraceSummaries", []))
        token = page.get("NextToken")
        if not token:
            break
    return ids


def _group_names(xr, max_pages=25):
    names = set()
    token = None
    for _ in range(max_pages):
        page = xr.get_groups(**({"NextToken": token} if token else {}))
        names.update(g["GroupName"] for g in page.get("Groups", []) if g.get("GroupName"))
        token = page.get("NextToken")
        if not token:
            break
    return names


def _error_code(fn):
    """(code, message) for a read-only call expected to be refused; raises if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be refused but succeeded: {result!r}")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A FilterExpression on ``metadata.<key>`` is refused by CreateGroup and GetTraceSummaries
    with the same parser error and creates no group; the ``annotation.`` form is accepted, stored
    verbatim, and selects the annotated trace but not one carrying the marker only in metadata.

    Reference: https://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html#xray-concepts-annotations
    """
    xr = ctx.client("xray")
    marker = _hex(10)
    bad_name = ctx.unique_name("sim2real-bh-xmd-")
    good_name = ctx.unique_name("sim2real-bh-xan-")
    bad_expr = f'metadata.probe_key = "{marker}"'
    good_expr = f'annotation.probe_key = "{marker}"'

    names_before = _group_names(xr)
    assert bad_name not in names_before and good_name not in names_before, (
        f"the freshly generated group names already exist in this account: "
        f"{sorted(names_before & {bad_name, good_name})!r}"
    )

    try:
        accepted = xr.create_group(GroupName=bad_name, FilterExpression=bad_expr)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == ERR_INVALID_REQUEST, (
            f"a group FilterExpression referencing metadata must be refused with "
            f"{ERR_INVALID_REQUEST!r}; an implementation that accepts it is promising a filter it "
            f"cannot honour, because metadata is not indexed: got {err.get('Code')!r}: "
            f"{err.get('Message')!r}"
        )
        assert err.get("Message") == MSG_UNKNOWN_SYMBOL, (
            f"the refusal must come from the expression parser at position 1 -- `metadata` is not "
            f"a field it knows -- got {err.get('Message')!r}"
        )
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, exc.response
    else:
        # Register cleanup before asserting so a wrongly accepted group does not leak.
        ctx.on_cleanup(lambda: xr.delete_group(GroupName=bad_name))
        raise AssertionError(
            f"CreateGroup accepted a FilterExpression on metadata, which X-Ray does not index: "
            f"{accepted!r}"
        )

    names_after = _group_names(xr)
    assert bad_name not in names_after, (
        f"a refused CreateGroup still created the group: {sorted(names_after - names_before)!r}"
    )
    assert len(names_after) == len(names_before), (
        f"the group count changed across a refused create: {len(names_before)} -> "
        f"{len(names_after)}"
    )

    created = xr.create_group(
        GroupName=good_name, FilterExpression=good_expr,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=good_name))
    assert created["Group"]["FilterExpression"] == good_expr, (
        f"the accepted group did not store the annotation expression verbatim: {created!r}"
    )
    stored = xr.get_group(GroupName=good_name)
    assert stored["Group"]["FilterExpression"] == good_expr, stored
    assert stored["Group"]["GroupARN"], (
        f"an accepted group must carry a GroupARN: {stored!r}"
    )

    now = time.time()
    metadata_trace = new_trace_id(now)
    annotated_trace = new_trace_id(now)
    docs = [
        json.dumps({
            "id": new_segment_id(), "name": "sim2real-behav-xray-md-" + _hex(6),
            "trace_id": metadata_trace, "start_time": now - 1.0, "end_time": now,
            "metadata": {"default": {"probe_key": marker}},
            "http": {"request": {"method": "GET", "url": "https://example.invalid/md"},
                     "response": {"status": 200}},
        }),
        json.dumps({
            "id": new_segment_id(), "name": "sim2real-behav-xray-an-" + _hex(6),
            "trace_id": annotated_trace, "start_time": now - 1.0, "end_time": now,
            "annotations": {"probe_key": marker},
            "http": {"request": {"method": "GET", "url": "https://example.invalid/an"},
                     "response": {"status": 200}},
        }),
    ]
    put = xr.put_trace_segments(TraceSegmentDocuments=docs)
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"both segments must be accepted -- carrying a marker in metadata is legal, it is only "
        f"unqueryable: {put!r}"
    )

    win_start, win_end = now - 300, now + 300
    unfiltered = _poll_until(
        lambda: _selected_ids(xr, win_start, time.time() + 60),
        lambda ids: {metadata_trace, annotated_trace} <= ids,
        timeout_s=_FILTER_TIMEOUT_S,
        interval_s=5,
        description="both the metadata-only and the annotated trace indexed",
    )
    assert {metadata_trace, annotated_trace} <= unfiltered, (
        f"both traces must be visible without a filter, or the selection below proves nothing: "
        f"missing {sorted({metadata_trace, annotated_trace} - unfiltered)!r}"
    )

    selected = _poll_until(
        lambda: _selected_ids(xr, win_start, win_end, expression=good_expr),
        lambda ids: annotated_trace in ids,
        timeout_s=_FILTER_TIMEOUT_S,
        interval_s=5,
        description="the annotated trace selected by the accepted annotation expression",
    )
    assert annotated_trace in selected, (
        f"the accepted annotation expression did not select the trace whose annotation carries the "
        f"marker, so acceptance did not make the expression functional: {sorted(selected)[:5]!r}"
    )
    assert metadata_trace not in selected, (
        f"the trace carrying the marker only in METADATA was selected by an annotation filter -- "
        f"confirming from the other direction that metadata is not an indexed field: "
        f"{sorted(selected)[:5]!r}"
    )

    read_code, read_message = _error_code(lambda: xr.get_trace_summaries(
        StartTime=_utc(win_start), EndTime=_utc(win_end), FilterExpression=bad_expr))
    assert read_code == ERR_INVALID_REQUEST, (
        f"GetTraceSummaries must refuse the same metadata expression CreateGroup refused, or an "
        f"implementation could validate on write and silently match nothing on read: got "
        f"{read_code!r}: {read_message!r}"
    )
    assert read_message == MSG_UNKNOWN_SYMBOL, (
        f"both surfaces must report the identical parser error, which is the evidence that one "
        f"expression language is shared rather than two validators being maintained: got "
        f"{read_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
