"""visibility-trace-retrieval-processing-window."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "visibility-trace-retrieval-processing-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["xray"]

_TERMINAL_RETRIEVAL_STATUSES = ("COMPLETE", "FAILED", "CANCELLED", "TIMEOUT")


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """ListRetrievedTraces returns no trace data while a retrieval is not yet terminal, and a
    COMPLETE retrieval eventually carries the submitted trace and no unrelated one.

    Reference: https://docs.aws.amazon.com/xray/latest/api/API_ListRetrievedTraces.html"""
    xray = ctx.client("xray")
    _enable_transaction_search(ctx)
    # One overall deadline, started once Transaction Search is ACTIVE.
    check_deadline = time.monotonic() + 280

    trace_id, segment_doc, start_time, end_time = _build_segment(ctx)
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment_doc)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    interval_s = 5
    saw_incomplete = False
    saw_complete_with_data = False
    last_status = None
    while time.monotonic() < check_deadline and not saw_complete_with_data:
        remaining = check_deadline - time.monotonic()
        # A job can reach COMPLETE before span indexing catches up and never gains data after,
        # so each attempt starts a fresh retrieval.
        token = _start_retrieval_with_retry(
            ctx, xray, [trace_id], start_time - 300, end_time + 300, max(1.0, remaining)
        )
        ctx.on_cleanup(lambda t=token: _best_effort_cancel(xray, t))

        while time.monotonic() < check_deadline:
            page = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
            last_status = page["RetrievalStatus"]
            assert last_status in ("SCHEDULED", "RUNNING", *_TERMINAL_RETRIEVAL_STATUSES), (
                f"unmodelled RetrievalStatus: {last_status!r}"
            )
            if last_status not in _TERMINAL_RETRIEVAL_STATUSES:
                saw_incomplete = True
                assert page.get("Traces", []) == [], (
                    f"non-terminal retrieval ({last_status}) already exposed trace data before "
                    "its processing window finished"
                )
                time.sleep(interval_s)
                continue
            traces = page.get("Traces", [])
            if last_status == "COMPLETE" and traces:
                unrelated = [t.get("Id") for t in traces if t.get("Id") != trace_id]
                assert not unrelated, (
                    f"COMPLETE retrieval surfaced trace(s) we never submitted: {unrelated}"
                )
            saw_complete_with_data = last_status == "COMPLETE" and any(
                t.get("Id") == trace_id for t in traces
            )
            assert last_status != "COMPLETE" or saw_complete_with_data or not traces, (
                f"COMPLETE retrieval returned trace data that does not include our submitted "
                f"trace {trace_id}: {[t.get('Id') for t in traces]}"
            )
            break  # terminal: either we have our data, or the next loop iteration retries fresh

    if not saw_incomplete:
        raise AssertionError(
            "every retrieval attempt reached a terminal state before the first poll could "
            "observe a pending state; the window was too tight in this run to validate "
            "premature-listing behavior"
        )
    if not saw_complete_with_data:
        raise AssertionError(
            "no retrieval attempt reached COMPLETE with our trace's data inside the overall "
            f"bounded window (last status observed: {last_status}); cannot confirm the "
            "eventual-visibility half of the contract"
        )


def _hex(n: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _build_segment(ctx):
    now = time.time()
    start_time = now - 5
    end_time = now
    trace_id = f"1-{format(int(now), 'x')}-{_hex(24)}"
    segment_id = _hex(16)
    name = ctx.unique_name("sim2real-behav-xrts-")
    doc = {
        "trace_id": trace_id,
        "id": segment_id,
        "name": name,
        "start_time": start_time,
        "end_time": end_time,
    }
    return trace_id, doc, start_time, end_time


def _enable_transaction_search(ctx) -> None:
    # UpdateTraceSegmentDestination(CloudWatchLogs) is denied until xray.amazonaws.com holds
    # logs:PutLogEvents on the span log groups. This is a CloudWatch Logs resource policy:
    # xray.put_resource_policy rejects this document as malformed.
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
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
                    f"arn:aws:logs:{region}:{account_id}:log-group:aws/spans:*",
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws/application-signals/data:*",
                ],
                "Condition": {
                    "ArnLike": {"aws:SourceArn": f"arn:aws:xray:{region}:{account_id}:*"},
                    "StringEquals": {"aws:SourceAccount": account_id},
                },
            }
        ],
    }
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(logs, policy_name))

    _pin_trace_segment_destination(ctx, "CloudWatchLogs", timeout_s=600.0)


def _start_retrieval_with_retry(ctx, xray, trace_ids, start_time, end_time, timeout_s):
    interval_s = 10
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return xray.start_trace_retrieval(
                TraceIds=trace_ids, StartTime=start_time, EndTime=end_time
            )["RetrievalToken"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"Transaction Search never surfaced ingested data for the submitted trace within "
        f"{timeout_s}s; log-group ingestion latency has no documented SLA (last error: "
        f"{last_exc})"
    )


def _best_effort_cancel(xray, token) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want` until cleanup; return the original.

    The destination is one setting per account and region and a switch takes minutes to settle."""
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
    # Restore is registered before the switch so a refused or unsettled switch is still undone;
    # a destination left on CloudWatchLogs makes GetTraceSummaries return nothing.
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
