"""start-trace-retrieval-results-not-immediately-available."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-trace-retrieval-results-not-immediately-available"
GROUP = "visibility-timeout-ttl"
SERVICES = ["xray"]

_TERMINAL = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """Right after StartTraceRetrieval, ListRetrievedTraces reports SCHEDULED/RUNNING with no
    Traces (a job already COMPLETE on that read is replaced by a fresh one); the job reaches
    COMPLETE and surfaces the submitted trace."""
    xray = ctx.client("xray")
    _ensure_cloudwatch_logs_resource_policy(ctx)
    _pin_trace_segment_destination(ctx, "CloudWatchLogs")

    trace_id, segment_doc, seg_start, seg_end = _build_segment(ctx)
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment_doc)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment was rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    # Transaction Search ingestion latency has no documented SLA: an early retrieval can COMPLETE
    # empty, so fresh jobs are retried within a bounded budget.
    deadline = time.monotonic() + _budget_s(ctx, 240.0)
    attempts = 0
    final = None
    saw_pending = False
    surfaced = False
    while True:
        attempts += 1
        token = _start_retrieval_once_indexed(
            xray, trace_id, seg_start - 300, seg_end + 300,
            timeout_s=max(1.0, deadline - time.monotonic()), interval_s=1.0, ctx=ctx,
        )
        ctx.on_cleanup(lambda t=token: _best_effort_cancel(xray, t))

        # A one-trace job can finish within the round trip; that attempt proves nothing about the
        # pending state, so another job is started until one is read before it completes.
        immediate = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
        assert immediate["RetrievalStatus"] in ("SCHEDULED", "RUNNING", "COMPLETE"), (
            f"expected a non-terminal status (or COMPLETE) immediately after StartTraceRetrieval, "
            f"got {immediate['RetrievalStatus']}"
        )
        if immediate["RetrievalStatus"] != "COMPLETE":
            saw_pending = True
            assert immediate.get("Traces", []) == [], (
                "Traces should be empty while the retrieval has not yet COMPLETEd"
            )

        final_status = _poll_retrieval_status(
            xray, token, timeout_s=max(1.0, deadline - time.monotonic()), interval_s=0.5, ctx=ctx
        )
        assert final_status == "COMPLETE", (
            f"expected the job to later reach COMPLETE, got {final_status}"
        )
        final = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
        assert final["RetrievalStatus"] == "COMPLETE", (
            f"expected the independent read to agree the retrieval is COMPLETE, "
            f"got {final['RetrievalStatus']}"
        )
        surfaced = surfaced or bool(final.get("Traces"))
        if surfaced and saw_pending:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("a pending-then-COMPLETE retrieval surfacing the trace: the run budget ended "
                                   "first; not graded")
            assert saw_pending, (
                f"all {attempts} retrieval(s) were already COMPLETE on the read right after "
                f"StartTraceRetrieval; none was observed SCHEDULED or RUNNING"
            )
            raise AssertionError(
                f"a COMPLETE retrieval never surfaced the submitted trace across {attempts} "
                f"attempt(s) within the retrieval budget -- Transaction Search ingestion "
                f"latency has no documented SLA"
            )
        time.sleep(1.0)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _ensure_cloudwatch_logs_resource_policy(ctx) -> None:
    """Put the Logs resource policy X-Ray needs to deliver spans; delete it in cleanup.

    UpdateTraceSegmentDestination(CloudWatchLogs) is refused until this policy exists."""
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


def _safe_delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _build_segment(ctx):
    now = datetime.now(timezone.utc)
    start_time = now.timestamp()
    end_time = start_time + 0.25
    trace_id = f"1-{int(start_time):08x}-{random.getrandbits(96):024x}"
    segment_id = f"{random.getrandbits(64):016x}"
    doc = {
        "name": ctx.unique_name("sim2real-behav-xrni-"),
        "id": segment_id,
        "trace_id": trace_id,
        "start_time": start_time,
        "end_time": end_time,
    }
    return trace_id, doc, start_time, end_time


def _start_retrieval_once_indexed(xray, trace_id, start_time, end_time, *, timeout_s, interval_s, ctx=None):
    """Retry StartTraceRetrieval past ResourceNotFoundException until Transaction Search has
    indexed the segment. An empty TraceIds list is rejected, so a real trace ID is required."""
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
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("StartTraceRetrieval accepting the ingested trace: the run budget ended first; not graded")
    raise AssertionError(
        f"StartTraceRetrieval never accepted the ingested trace ID within {timeout_s}s "
        f"(last error: {last_code})"
    )


def _poll_retrieval_status(xray, token: str, timeout_s: float = 300.0, interval_s: float = 5.0, ctx=None) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
        last_status = resp.get("RetrievalStatus")
        if last_status in _TERMINAL:
            return last_status
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"retrieval {token} reaching a terminal state: the run budget ended first; not graded")
    raise AssertionError(f"retrieval {token} never reached a terminal state (last={last_status})")


def _best_effort_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want`; return the one it found.

    A switch takes ~6 minutes PENDING -> ACTIVE; the restore is registered before switching."""
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
    original = _settled_trace_segment_destination(xray, timeout_s=_budget_s(ctx, timeout_s), ctx=ctx)[
        "Destination"
    ]
    ctx.on_cleanup(lambda: _restore_trace_segment_destination(xray, original, timeout_s=timeout_s))
    if original == want:
        return original
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            xray.update_trace_segment_destination(Destination=want)
            break
        except ClientError as err:
            # A just-put logs resource policy takes a while to reach X-Ray, which until then
            # refuses CloudWatchLogs naming the PutLogEvents permission it cannot yet see.
            message = err.response["Error"].get("Message", "")
            if "PutLogEvents" not in message or time.monotonic() >= deadline:
                if "PutLogEvents" in message and _budget_spent(ctx):
                    raise TimeoutError("UpdateTraceSegmentDestination seeing the logs resource policy: the run "
                                       "budget ended first; not graded") from err
                raise
            time.sleep(2.0)
    current = _settled_trace_segment_destination(xray, timeout_s=_budget_s(ctx, timeout_s), ctx=ctx)
    assert current["Destination"] == want, (
        f"trace-segment destination settled on {current!r} instead of {want}/ACTIVE"
    )
    return original


def _settled_trace_segment_destination(xray, *, timeout_s: float, ctx=None) -> dict:
    # AWS refuses UpdateTraceSegmentDestination while a previous switch is still PENDING.
    deadline = time.monotonic() + timeout_s
    while True:
        current = xray.get_trace_segment_destination()
        if current.get("Status") == "ACTIVE":
            return current
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError("the trace-segment destination settling ACTIVE: the run budget ended first; "
                                   "not graded")
            raise AssertionError(
                f"trace-segment destination still not ACTIVE after {timeout_s}s: {current!r}"
            )
        time.sleep(2.0)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Put the destination back and wait until it reads `original`/ACTIVE."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
