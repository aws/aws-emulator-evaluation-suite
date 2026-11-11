"""list-retrieved-traces-status-progresses-over-time."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-retrieved-traces-status-progresses-over-time"
GROUP = "visibility-timeout-ttl"
SERVICES = ["xray"]

UNKNOWN_TOKEN = "sim2real-behav-unknown-retrieval-token-0000000000"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """A StartTraceRetrieval job's status, read via ListRetrievedTraces, reaches COMPLETE within a
    bounded window, and an unissued token fails with InvalidRequestException."""
    xray = ctx.client("xray")
    # CloudWatchLogs activation takes ~6 minutes and is bounded on its own; the one deadline
    # below is then shared across the remaining setup AND the retrieval poll.
    _ensure_cloudwatch_logs_destination(ctx)
    deadline = time.monotonic() + 280

    # StartTraceRetrieval rejects TraceIds=[] ("Zero trace ids provided"), so a real trace is put
    # first and retrieval retried until Transaction Search has indexed it.
    trace_id, segment_doc, start_time, end_time = _build_segment(ctx)
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment_doc)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )
    token = _start_retrieval_with_retry(
        ctx, xray, [trace_id], start_time - 300, end_time + 300, deadline
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(xray, token))

    terminal = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}
    seen: list[str] = []
    status = None
    while time.monotonic() < deadline:
        status = xray.list_retrieved_traces(
            RetrievalToken=token, TraceFormat="XRAY"
        )["RetrievalStatus"]
        seen.append(status)
        if status in terminal:
            break
        time.sleep(5)
    if status not in terminal:
        raise AssertionError(f"retrieval never reached a terminal state, status history={seen}")
    assert status == "COMPLETE", (
        f"retrieval reached terminal state {status!r} instead of COMPLETE, status history={seen}"
    )

    code, message = _error(
        lambda: xray.list_retrieved_traces(
            RetrievalToken=UNKNOWN_TOKEN,
            TraceFormat="XRAY",
        )
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for an unissued RetrievalToken, got {code!r} ({message!r})"
    )
    assert message == f"Invalid execution id {UNKNOWN_TOKEN} passed: Invalid Execution Id", (
        f"MESSAGE={message!r}"
    )


def _hex(n: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _build_segment(ctx):
    now = time.time()
    start_time = now - 5
    end_time = now
    trace_id = f"1-{format(int(now), 'x')}-{_hex(24)}"
    doc = {
        "trace_id": trace_id,
        "id": _hex(16),
        "name": ctx.unique_name("sim2real-behav-xrlrt-"),
        "start_time": start_time,
        "end_time": end_time,
    }
    return trace_id, doc, start_time, end_time


def _start_retrieval_with_retry(ctx, xray, trace_ids, start_time, end_time, deadline: float):
    # StartTraceRetrieval raises ResourceNotFoundException until Transaction Search has indexed
    # the submitted segment.
    interval_s = 2
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
        f"Transaction Search never surfaced ingested data for the submitted trace before the "
        f"deadline; log-group ingestion latency has no documented SLA (last error: {last_exc})"
    )


def _best_effort_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _grant_transaction_search_delivery(ctx) -> None:
    """Put the Logs resource policy that lets X-Ray deliver spans; restore the prior one after.

    UpdateTraceSegmentDestination(CloudWatchLogs) is refused until this policy exists."""
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


def _ensure_cloudwatch_logs_destination(ctx) -> None:
    _grant_transaction_search_delivery(ctx)
    _pin_trace_segment_destination(ctx, "CloudWatchLogs", timeout_s=600.0)


def _error(fn):
    """-> (code, message) of the ClientError `fn` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


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
