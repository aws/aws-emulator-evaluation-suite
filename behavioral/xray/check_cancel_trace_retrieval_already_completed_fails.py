"""cancel-trace-retrieval-already-completed-fails."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-trace-retrieval-already-completed-fails"
GROUP = "overly-permissive"
SERVICES = ["xray"]

_TERMINAL = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """CancelTraceRetrieval on a COMPLETE retrieval succeeds and leaves its status COMPLETE, while on an
    active retrieval it moves the status to CANCELLED.
    """
    xray = ctx.client("xray")
    _ensure_transaction_search_log_policy(ctx)
    _pin_trace_segment_destination(ctx, "CloudWatchLogs")

    completed_trace_id = _put_indexed_trace(xray)
    completed_token = _start_retrieval_once_indexed(xray, completed_trace_id, timeout_s=180.0)
    status = _poll_retrieval_status(xray, completed_token, timeout_s=300)
    assert status == "COMPLETE", f"expected the setup job to reach COMPLETE, got {status}"

    xray.cancel_trace_retrieval(RetrievalToken=completed_token)  # must not raise -- real AWS no-ops here

    # the no-op cancel must not have mutated the job's recorded status
    post_status = xray.list_retrieved_traces(
        RetrievalToken=completed_token, TraceFormat="XRAY"
    )["RetrievalStatus"]
    assert post_status == "COMPLETE", f"cancel on a completed job changed its status: {post_status}"

    # positive control (same file): cancelling a job that IS still active succeeds
    active_trace_id = _put_indexed_trace(xray)
    active_token = _start_retrieval_once_indexed(xray, active_trace_id, timeout_s=180.0)
    ctx.on_cleanup(lambda: _safe_cancel(xray, active_token))
    xray.cancel_trace_retrieval(RetrievalToken=active_token)  # must not raise
    cancelled_status = _poll_retrieval_status(xray, active_token, timeout_s=300)
    assert cancelled_status == "CANCELLED", f"expected CANCELLED, got {cancelled_status}"


def _trace_id(epoch_seconds: int) -> str:
    return f"1-{epoch_seconds:08x}-{random.getrandbits(96):024x}"


def _segment_id() -> str:
    return f"{random.getrandbits(64):016x}"


def _put_indexed_trace(xray) -> str:
    now = datetime.now(timezone.utc)
    trace_id = _trace_id(int(now.timestamp()))
    segment = {
        "name": "sim2real-xray-cancel-already-completed-check",
        "id": _segment_id(),
        "trace_id": trace_id,
        "start_time": now.timestamp(),
        "end_time": now.timestamp() + 0.25,
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment was rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )
    return trace_id


def _start_retrieval_once_indexed(xray, trace_id: str, *, timeout_s: float, interval_s: float = 5.0) -> str:
    # StartTraceRetrieval 404s (ResourceNotFoundException) on a trace ID that has not been
    # indexed yet -- real AWS also rejects an empty TraceIds list outright, so a just-ingested,
    # real trace ID is the only way to get a retrieval job to cancel.
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=5)
    window_end = now + timedelta(minutes=5)
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = xray.start_trace_retrieval(
                TraceIds=[trace_id], StartTime=window_start, EndTime=window_end
            )
            return resp["RetrievalToken"]
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
    raise AssertionError(
        f"StartTraceRetrieval never accepted the ingested trace ID {trace_id} within "
        f"{timeout_s}s (last error: {last_code})"
    )


def _safe_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _ensure_transaction_search_log_policy(ctx) -> None:
    import json as _json

    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    logs = ctx.client("logs")
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
    logs.put_resource_policy(
        policyName="sim2real-xray-transaction-search-policy", policyDocument=_json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: _safe_delete_resource_policy(logs, "sim2real-xray-transaction-search-policy")
    )


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
            time.sleep(2)
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
        time.sleep(2)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Cleanup: put the destination back and WAIT until it reads `original`/ACTIVE, so the next
    check starts from the account state this one found rather than from a PENDING switch."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
