"""concurrent-start-trace-retrieval-same-window-dedupes."""
from __future__ import annotations

import json
import random
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-start-trace-retrieval-same-window-dedupes"
GROUP = "concurrency"
SERVICES = ["xray"]

_TERMINAL = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """Two concurrent StartTraceRetrieval calls for the same trace ID and window are not
    deduplicated: each gets a distinct RetrievalToken, and cancelling one leaves the other
    running to COMPLETE."""
    xray = ctx.client("xray")
    _grant_xray_put_log_events(ctx)
    _pin_trace_segment_destination(ctx, "CloudWatchLogs")

    now = datetime.now(timezone.utc)
    trace_id = _trace_id(int(now.timestamp()))
    segment = {
        "name": "sim2real-xray-concurrent-retrieval-check",
        "id": _segment_id(),
        "trace_id": trace_id,
        "start_time": now.timestamp(),
        "end_time": now.timestamp() + 0.25,
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment was rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    start_time = now - timedelta(minutes=5)
    end_time = now + timedelta(minutes=5)

    # Warm up: block on indexing lag (ResourceNotFoundException) once, outside the
    # concurrency window, so both racing calls below hit already-known-good state
    # rather than having the dedup signal confounded by indexing timing.
    warm_token = _start_retrieval_once_indexed(
        xray, trace_id, start_time, end_time, timeout_s=600.0, interval_s=5.0
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(xray, warm_token))

    def _start(_i):
        return xray.start_trace_retrieval(
            TraceIds=[trace_id], StartTime=start_time, EndTime=end_time
        )["RetrievalToken"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        token_a, token_b = list(pool.map(_start, range(2)))

    assert token_a and token_b, f"expected two non-empty retrieval tokens, got {token_a!r} {token_b!r}"
    assert token_a != token_b, "identical concurrent requests were deduped onto one token"
    assert warm_token not in (token_a, token_b), (
        "a request identical to the warm-up call was deduped onto the warm-up's token"
    )

    ctx.on_cleanup(lambda: _best_effort_cancel(xray, token_a))
    ctx.on_cleanup(lambda: _best_effort_cancel(xray, token_b))

    # CancelTraceRetrieval on a known token never raises; A may finish before the cancel
    # lands, so it settles on CANCELLED or COMPLETE, never FAILED or TIMEOUT.
    xray.cancel_trace_retrieval(RetrievalToken=token_a)  # must not raise
    status_a_after = _poll_retrieval_status(xray, token_a, timeout_s=300)
    assert status_a_after in ("CANCELLED", "COMPLETE"), (
        f"job A must settle on CANCELLED or COMPLETE after the cancel, got {status_a_after}"
    )

    # Job B was never cancelled, so it runs to COMPLETE on its own.
    status_b_after = _poll_retrieval_status(xray, token_b, timeout_s=300)
    assert status_b_after == "COMPLETE", (
        f"cancelling job A must leave job B to complete on its own, got {status_b_after}"
    )


def _trace_id(epoch_seconds: int) -> str:
    return f"1-{epoch_seconds:08x}-{random.getrandbits(96):024x}"


def _segment_id() -> str:
    return f"{random.getrandbits(64):016x}"


def _start_retrieval_once_indexed(xray, trace_id, start_time, end_time, *, timeout_s, interval_s):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = xray.start_trace_retrieval(
                TraceIds=[trace_id], StartTime=start_time, EndTime=end_time
            )
            return resp["RetrievalToken"]
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
    raise AssertionError(
        f"StartTraceRetrieval never accepted the ingested trace ID within {timeout_s}s "
        f"(last error: {last_code})"
    )


def _grant_xray_put_log_events(ctx) -> None:
    """CloudWatchLogs Transaction Search fails UpdateTraceSegmentDestination with
    AccessDeniedException until XRay is granted PutLogEvents on the aws/spans log
    group via a CloudWatch Logs resource policy -- AWS does not provision this for you."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    logs = ctx.client("logs")
    policy_name = "sim2real-xray-concurrent-retrieval-transaction-search-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TransactionSearchXRayAccess",
                "Effect": "Allow",
                "Principal": {"Service": "xray.amazonaws.com"},
                "Action": "logs:PutLogEvents",
                "Resource": [
                    f"arn:aws:logs:{region}:{account}:log-group:aws/spans:*",
                    f"arn:aws:logs:{region}:{account}:log-group:/aws/application-signals/data:*",
                ],
                "Condition": {
                    "ArnLike": {"aws:SourceArn": f"arn:aws:xray:{region}:{account}:*"},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }
        ],
    }
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(logs, policy_name))


def _safe_delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_retrieval_status(xray, token: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
        last_status = resp.get("RetrievalStatus")
        if last_status in _TERMINAL:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"retrieval {token} never reached a terminal state (last={last_status})")


def _best_effort_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
