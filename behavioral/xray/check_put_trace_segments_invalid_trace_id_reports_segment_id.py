"""put-trace-segments-invalid-trace-id-reports-segment-id."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-trace-segments-invalid-trace-id-reports-segment-id"
GROUP = 'trace-data-plane'
SERVICES = ['xray']


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    """Generate a syntactically valid X-Ray segment ID: 16 hex chars."""
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=60, interval_s=2, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _settled_trace_segment_destination(xr, *, timeout_s: float = 600.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        current = xr.get_trace_segment_destination()
        if current.get("Status") == "ACTIVE":
            return current
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"trace-segment destination still not ACTIVE after {timeout_s}s: {current!r}"
            )
        time.sleep(2.0)


def _restore_trace_segment_destination(xr, original: str) -> None:
    if _settled_trace_segment_destination(xr)["Destination"] != original:
        xr.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xr)


def _pin_trace_segment_destination(ctx, xr, want: str) -> None:
    """Pins the account-wide trace-segment destination to `want`, restoring it on cleanup.

    PutTraceSegments only ingests directly when the destination is XRay; a sibling check
    that left it on CloudWatchLogs would otherwise make every segment here unprocessable
    for a reason that has nothing to do with the malformed trace_id under test.
    """
    original = _settled_trace_segment_destination(xr)["Destination"]
    ctx.on_cleanup(lambda: _restore_trace_segment_destination(xr, original))
    if original == want:
        return
    xr.update_trace_segment_destination(Destination=want)
    current = _settled_trace_segment_destination(xr)
    assert current["Destination"] == want, (
        f"trace-segment destination settled on {current!r} instead of {want}/ACTIVE"
    )


ERR_READ_FORMAT = 'InvalidRequestException'
"""BatchGetTraces' refusal of a trace id that does not match ``1-<8 hex>-<24 hex>``.

Verified on real AWS (us-west-2): the READ path validates the trace id format too --
``batch_get_traces(TraceIds=['1-<8hex>-<20hex>'])`` raises InvalidRequestException "Invalid trace
id <id>: incorrect id format" rather than answering with an empty Traces list. A well-formed id
that was never submitted is a different answer entirely: 200, Traces == [].
"""


def _read_error(xr, trace_id):
    """-> (error_code, message) of the refused BatchGetTraces call; a read that succeeds fails the check."""
    try:
        result = xr.batch_get_traces(TraceIds=[trace_id])
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected BatchGetTraces({trace_id!r}) to be refused, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """A segment with a malformed trace_id is reported in UnprocessedTraceSegments under its own id
    as InvalidTraceId in a 200, without suppressing a valid sibling; BatchGetTraces then refuses the
    malformed id, while a well-formed unknown id reads back empty.
    """
    xr = ctx.client("xray")
    _pin_trace_segment_destination(ctx, xr, "XRay")
    now = time.time()

    good_trace_id = new_trace_id(now)
    good_seg_id = new_segment_id()
    good = {
        "id": good_seg_id,
        "name": "sim2real-behav-xray-good",
        "trace_id": good_trace_id,
        "start_time": now - 1.0,
        "end_time": now,
    }

    # Malformed trace_id: correct "1-" version and 8-hex epoch, but only 20 hex in the random
    # part instead of the required 24. Total length is 31 chars, i.e. still inside TraceId's
    # modeled length 1..35, so the rejection below is the service's own semantic validation and
    # not a client-side length constraint.
    bad_trace_id = f"1-{int(now):08x}-{_hex(20)}"
    bad_seg_id = new_segment_id()
    bad = {
        "id": bad_seg_id,
        "name": "sim2real-behav-xray-bad-traceid",
        "trace_id": bad_trace_id,
        "start_time": now - 1.0,
        "end_time": now,
    }

    resp = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(good), json.dumps(bad)])
    # The whole call succeeds: partial failure is reported in the body, not as an HTTP error.
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, resp
    unprocessed = resp.get("UnprocessedTraceSegments", [])
    assert len(unprocessed) == 1, (
        f"expected exactly 1 unprocessed segment (the malformed trace_id), got {unprocessed!r}"
    )
    entry = unprocessed[0]
    assert entry.get("Id") == bad_seg_id, (
        f"UnprocessedTraceSegments entry must be keyed by the rejected segment's own id "
        f"{bad_seg_id!r}, got {entry!r}"
    )
    # The per-segment error names WHICH part of the document was wrong -- not a generic failure.
    assert entry.get("ErrorCode") == "InvalidTraceId", (
        f"expected the per-segment ErrorCode to identify the malformed trace_id as "
        f"'InvalidTraceId', got {entry.get('ErrorCode')!r}"
    )
    assert entry.get("Message") == "Invalid segment. ErrorCode: InvalidTraceId", (
        f"expected the per-segment Message to restate the error code, got "
        f"{entry.get('Message')!r}"
    )

    # The valid sibling in the same batch was accepted and is retrievable.
    result = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[good_trace_id]),
        lambda r: len(r.get("Traces", [])) == 1,
        timeout_s=60,
        interval_s=2,
        description="valid segment from a partially-rejected batch is retrievable",
    )
    assert result["Traces"][0]["Id"] == good_trace_id, result
    assert result.get("UnprocessedTraceIds", []) == [], result

    # X-Ray validates the trace-id format on reads too, so the malformed id is refused rather than
    # answered empty; the sibling has landed, so this is not indexing lag.
    code, message = _read_error(xr, bad_trace_id)
    assert code == ERR_READ_FORMAT, (
        f"reading the malformed trace id {bad_trace_id!r} must be refused with "
        f"{ERR_READ_FORMAT}, got code={code!r} message={message!r}"
    )
    assert message == f"Invalid trace id {bad_trace_id}: incorrect id format", (
        f"the read-path refusal must name the offending id and the reason, got {message!r}"
    )

    # The refusal is about the format, not absence: a well-formed unknown id is answered, not refused.
    never_submitted = new_trace_id(now)
    try:
        absent = xr.batch_get_traces(TraceIds=[never_submitted])
    except ClientError as exc:
        raise AssertionError(
            f"a well-formed but never-submitted trace id must be answered, not refused, got "
            f"{exc.response['Error']!r}"
        ) from exc
    assert absent.get("Traces", []) == [], (
        f"a never-submitted trace id must read back as an empty Traces list, got {absent!r}"
    )
    assert absent.get("UnprocessedTraceIds", []) == [], (
        f"an unknown-but-well-formed trace id is not an unprocessable one, got {absent!r}"
    )

    # The rejection is a property of the segment, not of being batched with a valid sibling.
    alone_seg_id = new_segment_id()
    alone = xr.put_trace_segments(
        TraceSegmentDocuments=[json.dumps(dict(bad, id=alone_seg_id))]
    )
    alone_unprocessed = alone.get("UnprocessedTraceSegments", [])
    assert len(alone_unprocessed) == 1 and alone_unprocessed[0].get("Id") == alone_seg_id, (
        f"submitted on its own, the malformed segment must still be reported keyed by its own "
        f"id rather than failing the call, got {alone!r}"
    )
    assert alone_unprocessed[0].get("ErrorCode") == "InvalidTraceId", alone_unprocessed[0]
    assert alone["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"a batch in which EVERY segment is rejected is still a 200 with per-segment errors, "
        f"got {alone!r}"
    )

    # Control: the same segment body with a well-formed trace_id is accepted and lands.
    fixed_trace_id = new_trace_id(now)
    fixed = dict(bad, trace_id=fixed_trace_id, id=new_segment_id())
    retry = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(fixed)])
    assert retry.get("UnprocessedTraceSegments", []) == [], (
        f"corrected segment must be accepted, got {retry!r}"
    )
    fixed_result = _poll_until(
        lambda: xr.batch_get_traces(TraceIds=[fixed_trace_id]),
        lambda r: len(r.get("Traces", [])) == 1,
        timeout_s=60,
        interval_s=2,
        description="corrected segment retrievable",
    )
    assert fixed_result["Traces"][0]["Id"] == fixed_trace_id, fixed_result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
