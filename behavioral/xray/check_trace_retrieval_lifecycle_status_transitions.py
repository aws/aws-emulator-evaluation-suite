"""trace-retrieval-lifecycle-status-transitions."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trace-retrieval-lifecycle-status-transitions"
GROUP = "state-machine"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """A retrieval started for an indexed trace is read SCHEDULED or RUNNING in
    ListRetrievedTraces before it reaches COMPLETE."""
    xray = ctx.client("xray")
    _ensure_transaction_search_enabled(xray, ctx)

    now = datetime.now(timezone.utc)
    trace_id = _trace_id(int(now.timestamp()))
    segment = {
        "name": "sim2real-xray-lifecycle-check",
        "id": _segment_id(),
        "trace_id": trace_id,
        "start_time": now.timestamp(),
        "end_time": now.timestamp() + 0.25,
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment was rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    window_start = now - timedelta(minutes=5)
    window_end = now + timedelta(minutes=5)

    token = _start_retrieval_once_indexed(
        xray, trace_id, window_start, window_end, timeout_s=180.0, interval_s=5.0
    )
    # A one-trace retrieval can already be COMPLETE on the read right after its start, so fresh
    # retrievals are started until one is read SCHEDULED or RUNNING; every one must end COMPLETE.
    first_statuses = []
    for attempt in range(_ATTEMPTS):
        if attempt and _budget_spent(ctx):
            raise TimeoutError(
                f"a retrieval read non-terminal: the run budget ended first; first reads {first_statuses}; not graded"
            )
        if attempt:
            token = xray.start_trace_retrieval(
                TraceIds=[trace_id], StartTime=window_start, EndTime=window_end
            )["RetrievalToken"]
        ctx.on_cleanup(lambda t=token: _safe_cancel(xray, t))
        first_status = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")["RetrievalStatus"]
        first_statuses.append(first_status)
        assert first_status in ("SCHEDULED", "RUNNING", "COMPLETE"), (
            f"retrieval read {first_status} right after StartTraceRetrieval; reads so far: {first_statuses}"
        )
        final_status = _poll_until_terminal(ctx, xray, token, timeout_s=_budget_s(ctx, 120.0), interval_s=3.0)
        assert final_status == "COMPLETE", (
            f"retrieval for an indexed trace did not reach COMPLETE (ended in {final_status})"
        )
        if first_status != "COMPLETE":
            return
    raise AssertionError(
        f"no retrieval began in a non-terminal state in {_ATTEMPTS} attempts; first reads: {first_statuses}"
    )


_ATTEMPTS = 10


_TERMINAL = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}


def _trace_id(epoch_seconds: int) -> str:
    return f"1-{epoch_seconds:08x}-{random.getrandbits(96):024x}"


def _segment_id() -> str:
    return f"{random.getrandbits(64):016x}"


def _start_retrieval_once_indexed(xray, trace_id, start_time, end_time, *, timeout_s, interval_s):
    """StartTraceRetrieval raises ResourceNotFoundException until Transaction Search
    has indexed the segment into its CloudWatch Logs group; retry until it accepts the
    trace ID (or a genuinely different error surfaces)."""
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


def _poll_until_terminal(ctx, xray, token, *, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")["RetrievalStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("the retrieval reaching a terminal status: the run budget ended first; not graded")
    raise AssertionError(f"retrieval never reached a terminal status (last seen: {status})")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _ensure_transaction_search_enabled(xray, ctx, timeout_s: float = 600.0) -> None:
    import json as _json

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
    logs.put_resource_policy(policyName=policy_name, policyDocument=_json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(logs, policy_name))

    _pin_trace_segment_destination(ctx, "CloudWatchLogs", timeout_s=timeout_s)


def _safe_delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_cancel(xray, token: str) -> None:
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
