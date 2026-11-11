"""cancel-trace-retrieval-stops-in-progress-retrieval."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-trace-retrieval-stops-in-progress-retrieval"
GROUP = "state-machine"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """A cancel reaching a running retrieval lands it in CANCELLED with no traces, while an
    un-cancelled retrieval of the same trace reaches COMPLETE with it; a late cancel leaves
    the retrieval COMPLETE with its trace."""
    xray = ctx.client("xray")
    _ensure_transaction_search_enabled(xray, ctx)

    now = datetime.now(timezone.utc)
    trace_id = _trace_id(int(now.timestamp()))
    segment = {
        "name": "sim2real-xray-cancel-check",
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

    # Positive control: a retrieval for the indexed trace, NOT cancelled, completes with it.
    control_token = _start_retrieval_once_indexed(
        xray, trace_id, window_start, window_end, timeout_s=_budget_s(ctx, 180.0), interval_s=1.0, ctx=ctx
    )
    ctx.on_cleanup(lambda: _safe_cancel(xray, control_token))
    control_final = _poll_until_terminal(
        xray, control_token, timeout_s=_budget_s(ctx, 120.0), interval_s=0.5, ctx=ctx
    )
    assert control_final == "COMPLETE", (
        f"un-cancelled control retrieval ended in {control_final}, expected COMPLETE"
    )
    control_ids = _retrieved_trace_ids(xray, control_token)
    assert control_ids == {trace_id}, (
        f"completed control retrieval returned traces {control_ids}, expected {{{trace_id!r}}}"
    )

    outcomes = _cancel_until_cancelled(ctx, xray, trace_id, window_start, window_end)
    assert outcomes[-1] == ("CANCELLED", set()), f"cancel attempts: {outcomes}"


_TERMINAL = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _trace_id(epoch_seconds: int) -> str:
    return f"1-{epoch_seconds:08x}-{random.getrandbits(96):024x}"


def _segment_id() -> str:
    return f"{random.getrandbits(64):016x}"


def _start_retrieval_once_indexed(xray, trace_id, start_time, end_time, *, timeout_s, interval_s, ctx=None):
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


def _retrieved_trace_ids(xray, token: str) -> set:
    resp = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
    return {t.get("Id") for t in resp.get("Traces", [])}


def _cancel_until_cancelled(ctx, xray, trace_id, start_time, end_time, *, attempts: int = 20):
    """Start a retrieval and cancel it at once, until a cancel lands while it is still running.

    A one-trace retrieval finishes in under a second, so a cancel lands in time only part of
    the time. Every attempt is graded. Returns [(status, trace ids)] per attempt."""
    outcomes = []
    for _ in range(attempts):
        token = xray.start_trace_retrieval(
            TraceIds=[trace_id], StartTime=start_time, EndTime=end_time
        )["RetrievalToken"]
        ctx.on_cleanup(lambda t=token: _safe_cancel(xray, t))
        xray.cancel_trace_retrieval(RetrievalToken=token)
        status = _poll_until_terminal(xray, token, timeout_s=_budget_s(ctx, 60.0), interval_s=0.5, ctx=ctx)
        ids = _retrieved_trace_ids(xray, token)
        outcomes.append((status, ids))
        if status == "CANCELLED":
            assert ids == set(), f"cancelled retrieval returned traces {ids}"
            return outcomes
        assert status == "COMPLETE", (
            f"cancelled retrieval ended in {status}, expected CANCELLED or (cancel too late) "
            f"COMPLETE; attempts: {outcomes}"
        )
        assert ids == {trace_id}, (
            f"retrieval that completed before its cancel returned traces {ids}, expected "
            f"{{{trace_id!r}}}"
        )
    raise AssertionError(
        f"no cancel reached a running retrieval in {attempts} attempts: {outcomes}"
    )


def _poll_until_terminal(xray, token, *, timeout_s: float, interval_s: float, ctx=None) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")["RetrievalStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the retrieval reaching a terminal status: the run budget ended first; not graded")
    raise AssertionError(f"retrieval never reached a terminal status (last seen: {status})")


def _ensure_transaction_search_enabled(xray, ctx, timeout_s: float = 600.0) -> None:
    _grant_transaction_search_delivery(ctx)
    _pin_trace_segment_destination(ctx, "CloudWatchLogs", timeout_s=timeout_s)


def _grant_transaction_search_delivery(ctx) -> None:
    """Put the CloudWatch Logs resource policy that lets X-Ray deliver spans, and restore what
    the account held under that name afterwards.

    UpdateTraceSegmentDestination(CloudWatchLogs) is refused until a CloudWatch Logs resource
    policy grants xray.amazonaws.com logs:PutLogEvents on the spans log groups. The policy name
    is shared by every Transaction Search check, so the document found under it is put back in
    cleanup, and the policy is deleted only when the check created it."""
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
    original = _existing_resource_policy(logs, policy_name)
    if original is None:
        ctx.on_cleanup(lambda: logs.delete_resource_policy(policyName=policy_name))
    else:
        ctx.on_cleanup(
            lambda: logs.put_resource_policy(policyName=policy_name, policyDocument=original)
        )
    logs.put_resource_policy(policyName=policy_name, policyDocument=_json.dumps(policy_doc))


def _existing_resource_policy(logs, policy_name: str):
    """-> the policy document the account holds under `policy_name`, or None when it holds none."""
    kwargs: dict = {}
    while True:
        resp = logs.describe_resource_policies(**kwargs)
        for policy in resp.get("resourcePolicies", []):
            if policy.get("policyName") == policy_name:
                return policy["policyDocument"]
        if not resp.get("nextToken"):
            return None
        kwargs["nextToken"] = resp["nextToken"]


def _safe_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    """Cleanup: put the destination back and WAIT until it reads `original`/ACTIVE, so the next
    check starts from the account state this one found rather than from a PENDING switch."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
