"""put-trace-segments-unicode-annotation-round-trip."""
from __future__ import annotations

import json
import os
import time

from behavioral_harness import tags

CHECK = "put-trace-segments-unicode-annotation-round-trip"
GROUP = "representation"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:xray-encryption", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """Unicode characters in a segment's annotations/metadata survive a
    PutTraceSegments -> BatchGetTraces round trip byte-for-byte."""
    xray = ctx.client("xray")
    _ensure_none_encryption(ctx, xray)
    _pin_trace_segment_destination(ctx, "XRay")

    trace_id = _make_trace_id()
    segment_id = _make_segment_id()
    now = time.time()
    unicode_annotation = "cafe-\u00e9\u65e5\u672c\u8a9e-\U0001f680-\u0645\u0631\u062d\u0628\u0627"
    unicode_metadata = "\u00fcbermensch-\u4e2d\u6587-\U0001f600-\u00e9\u00e8\u00ea"
    document = {
        "trace_id": trace_id,
        "id": segment_id,
        "name": ctx.unique_name("sim2real-xray-behav"),
        "start_time": now,
        "end_time": now + 0.25,
        "annotations": {"greeting": unicode_annotation},
        "metadata": {"custom": {"note": unicode_metadata}},
    }
    resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(document)])
    unprocessed = resp["UnprocessedTraceSegments"]
    assert unprocessed == [], f"expected no unprocessed segments, got {unprocessed}"

    fetched = _wait_for_trace_document(ctx, trace_id, timeout_s=90.0)
    actual_annotation = fetched["annotations"]["greeting"]
    assert actual_annotation == unicode_annotation, (
        f"annotation mismatch: expected {unicode_annotation!r}, got {actual_annotation!r}"
    )
    actual_metadata = fetched["metadata"]["custom"]["note"]
    assert actual_metadata == unicode_metadata, (
        f"metadata mismatch: expected {unicode_metadata!r}, got {actual_metadata!r}"
    )


def _ensure_none_encryption(ctx, xray) -> None:
    """A lingering KMS encryption config from an unrelated run can silently prevent
    segments from ever becoming queryable; force plain (NONE) encryption for this check."""
    original = xray.get_encryption_config()["EncryptionConfig"]
    if original.get("Type") == "NONE":
        return
    xray.put_encryption_config(Type="NONE")
    if original.get("Type") == "KMS" and original.get("KeyId"):
        original_key_id = original["KeyId"]
        ctx.on_cleanup(lambda: xray.put_encryption_config(Type="KMS", KeyId=original_key_id))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        config = xray.get_encryption_config()["EncryptionConfig"]
        if config.get("Type") == "NONE":
            return
        time.sleep(5)


def _make_trace_id() -> str:
    return f"1-{int(time.time()):08x}-{os.urandom(12).hex()}"


def _make_segment_id() -> str:
    return os.urandom(8).hex()


def _wait_for_trace_document(ctx, trace_id: str, timeout_s: float = 90.0) -> dict:
    xray = ctx.client("xray")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = xray.batch_get_traces(TraceIds=[trace_id])
        traces = resp.get("Traces", [])
        if traces:
            segments = traces[0].get("Segments", [])
            if segments:
                return json.loads(segments[0]["Document"])
        time.sleep(2.0)
    raise AssertionError(f"trace {trace_id} never became retrievable via BatchGetTraces within {timeout_s}s")


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
