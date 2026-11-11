"""get-retrieved-traces-graph-unknown-token-fails."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-retrieved-traces-graph-unknown-token-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """GetRetrievedTracesGraph with an unissued RetrievalToken fails with InvalidRequestException,
    while a token issued for a just-ingested trace is accepted."""
    xr = ctx.client("xray")
    _ensure_transaction_search_enabled(xr, ctx)

    now = datetime.now(timezone.utc)
    trace_id = _trace_id(int(now.timestamp()))
    segment = {
        "name": "sim2real-xray-graph-unknown-token-check",
        "id": _segment_id(),
        "trace_id": trace_id,
        "start_time": now.timestamp(),
        "end_time": now.timestamp() + 0.25,
    }
    put_resp = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment was rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    window_start = now - timedelta(minutes=5)
    window_end = now + timedelta(minutes=5)
    token = _start_retrieval_once_indexed(
        xr, trace_id, window_start, window_end, timeout_s=180.0, interval_s=5.0
    )
    ctx.on_cleanup(lambda: _safe_cancel(xr, token))

    real_graph = xr.get_retrieved_traces_graph(RetrievalToken=token)
    assert real_graph.get("RetrievalStatus") in ("SCHEDULED", "RUNNING", "COMPLETE"), (
        f"a genuinely issued token was not accepted: {real_graph}"
    )

    bogus_token = "sim2real-behav-not-a-real-token"
    code, message = _error(lambda: xr.get_retrieved_traces_graph(RetrievalToken=bogus_token))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == (
        f"Invalid execution id {bogus_token} passed: Invalid Execution Id"
    ), f"unexpected message: {message!r}"


def _trace_id(epoch_seconds: int) -> str:
    return f"1-{epoch_seconds:08x}-{random.getrandbits(96):024x}"


def _segment_id() -> str:
    return f"{random.getrandbits(64):016x}"


def _start_retrieval_once_indexed(xr, trace_id, start_time, end_time, *, timeout_s, interval_s):
    """StartTraceRetrieval raises ResourceNotFoundException until Transaction Search has
    indexed the segment into its CloudWatch Logs group; retry until it accepts the trace ID
    (or a genuinely different error surfaces)."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = xr.start_trace_retrieval(TraceIds=[trace_id], StartTime=start_time, EndTime=end_time)
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


def _ensure_transaction_search_enabled(xr, ctx, timeout_s: float = 600.0) -> None:
    """Point the trace-segment destination at CloudWatchLogs (Transaction Search) and wait ACTIVE.

    The required policy is a Logs resource policy; X-Ray's own PutResourcePolicy rejects it."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    logs = ctx.client("logs")
    policy_name = "sim2real-xray-transaction-search-policy"
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

    _pin_trace_segment_destination(ctx, "CloudWatchLogs", timeout_s=timeout_s)


def _safe_delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_cancel(xr, token: str) -> None:
    try:
        xr.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want`; return the one it found.

    A switch takes ~6 minutes PENDING -> ACTIVE; the restore is registered before switching."""
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
    """Put the destination back and wait until it reads `original`/ACTIVE."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
