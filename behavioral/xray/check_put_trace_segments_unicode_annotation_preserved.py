"""put-trace-segments-unicode-annotation-preserved."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-trace-segments-unicode-annotation-preserved"
GROUP = "representation"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:xray-encryption", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """Unicode/emoji annotation values embedded in a PutTraceSegments document survive
    ingestion and are returned byte-for-byte unchanged by BatchGetTraces."""
    xray = ctx.client("xray")
    # PutTraceSegments/BatchGetTraces need a working encryption path; a stuck/lingering
    # KMS encryption config from an unrelated test (e.g. mid-transition to a CMK) can
    # silently prevent segments from ever becoming queryable. Force plain (NONE)
    # encryption for the duration of this check.
    _ensure_none_encryption(ctx, xray)
    # BatchGetTraces cannot see a trace at all while the account's trace segment
    # destination is CloudWatchLogs (Transaction Search) — traces are indexed there
    # instead of in classic X-Ray. Force the classic XRay destination for the duration
    # of this check and restore whatever was configured before.
    _pin_trace_segment_destination(ctx, "XRay")

    trace_id = _new_trace_id()
    now = time.time()
    unicode_value = "caf\u00e9 \u2615 \u65e5\u672c\u8a9e \U0001F680"
    segment_id = uuid.uuid4().hex[:16]
    segment = {
        "trace_id": trace_id,
        "id": segment_id,
        "name": "sim2real-behav-segment",
        "start_time": now,
        "end_time": now + 0.25,
        "annotations": {"unicode_note": unicode_value},
    }
    resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert not resp.get("UnprocessedTraceSegments"), resp.get("UnprocessedTraceSegments")

    trace = _poll_for_trace(xray, trace_id)
    documents = [json.loads(s["Document"]) for s in trace["Segments"]]
    matching = [d for d in documents if d.get("id") == segment_id]
    assert len(matching) == 1, f"expected exactly one matching segment, got {documents}"
    actual_value = matching[0]["annotations"]["unicode_note"]
    assert actual_value == unicode_value, f"expected annotation {unicode_value!r}, got {actual_value!r}"


def _ensure_none_encryption(ctx, xray) -> None:
    original = xray.get_encryption_config()["EncryptionConfig"]
    if original.get("Type") == "NONE":
        return
    xray.put_encryption_config(Type="NONE")
    if original.get("Type") == "KMS" and original.get("KeyId"):
        original_key_id = original["KeyId"]
        ctx.on_cleanup(lambda: xray.put_encryption_config(Type="KMS", KeyId=original_key_id))
    # Don't require Status==ACTIVE (that transition can be very slow); firing the switch
    # to NONE is enough to unblock plain-text segment storage for this check.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        config = xray.get_encryption_config()["EncryptionConfig"]
        if config.get("Type") == "NONE":
            return
        time.sleep(5)
    raise AssertionError(
        f"encryption config never settled to NONE in time, last saw {config.get('Type')}"
    )


def _new_trace_id() -> str:

    epoch = format(int(time.time()), "x")
    return f"1-{epoch}-{uuid.uuid4().hex[:24]}"


def _poll_for_trace(xray, trace_id: str, timeout_s: float = 240.0, interval_s: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout_s
    saw_summary = False
    while time.monotonic() < deadline:
        resp = xray.batch_get_traces(TraceIds=[trace_id])
        if resp.get("Traces"):
            return resp["Traces"][0]
        if not saw_summary:
            try:
                now = datetime.now(timezone.utc)
                summaries = xray.get_trace_summaries(
                    StartTime=now - timedelta(minutes=10),
                    EndTime=now + timedelta(minutes=1),
                    TimeRangeType="Event",
                )["TraceSummaries"]
                saw_summary = any(s.get("Id") == trace_id for s in summaries)
            except Exception:  # noqa: BLE001
                pass
        time.sleep(interval_s)
    enc = dest = ""
    try:
        enc = xray.get_encryption_config()["EncryptionConfig"].get("Type", "?")
    except Exception:  # noqa: BLE001
        pass
    try:
        dest = xray.get_trace_segment_destination().get("Destination", "?")
    except Exception:  # noqa: BLE001
        pass
    raise AssertionError("nf;summ=" + str(saw_summary) + ";enc=" + str(enc) + ";dst=" + str(dest))


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
