"""start-trace-retrieval-unknown-destination-not-found."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-trace-retrieval-unknown-destination-not-found"
GROUP = "error-semantics"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """CancelTraceRetrieval rejects a one-character mutation of a real RetrievalToken with
    InvalidRequestException and its exact message and leaves the real job uncancelled; the
    genuine token is still accepted once its job is COMPLETE: the token is integrity-checked."""
    xray = ctx.client("xray")
    # StartTraceRetrieval returns ResourceNotFoundException unless the destination is
    # CloudWatchLogs (Transaction Search) and a segment for the trace ID has been ingested.
    _ensure_transaction_search_enabled(ctx, xray)

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=10)
    end_time = now
    trace_id = _trace_id(int(now.timestamp()))
    seg = {
        "name": "sim2real-probe-seed",
        "id": "".join(random.choices("0123456789abcdef", k=16)),
        "trace_id": trace_id,
        "start_time": now.timestamp() - 5,
        "end_time": now.timestamp(),
    }
    xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg)])

    # Retries past the delay before the ingested segment becomes retrievable.
    token = _start_retrieval_with_retry(
        xray, trace_id, start_time, end_time, timeout_s=_budget_s(ctx, 150.0), ctx=ctx
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(xray, token))

    mutated_token = _mutate_token(token)
    code, message = _error_code(lambda: xray.cancel_trace_retrieval(RetrievalToken=mutated_token))
    assert code == "InvalidRequestException", f"unexpected error code: {code}"
    expected_message = (
        f"Invalid retrieval token {mutated_token} passed: Invalid execution id provided: "
        f"{mutated_token}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unaffected_status = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")["RetrievalStatus"]
    assert unaffected_status != "CANCELLED", (
        f"a cancel rejected with InvalidRequestException still moved the real job to "
        f"CANCELLED (status={unaffected_status!r})"
    )

    # The genuine cancel is sent once the job is terminal, so every run grades the same state:
    # AWS accepts it as a no-op and the job keeps its terminal status.
    settled = _poll_retrieval_status(ctx, xray, token, timeout_s=_budget_s(ctx, 120.0))
    assert settled == "COMPLETE", f"the uncancelled retrieval ended {settled!r}, expected COMPLETE"
    xray.cancel_trace_retrieval(RetrievalToken=token)
    final_status = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")["RetrievalStatus"]
    assert final_status == "COMPLETE", (
        f"CancelTraceRetrieval with the genuine token changed a COMPLETE job to {final_status!r}"
    )


_TERMINAL = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}


def _poll_retrieval_status(ctx, xray, token: str, *, timeout_s: float, interval_s: float = 2.0) -> str:
    """The retrieval's first terminal RetrievalStatus, polled within timeout_s."""
    deadline = time.monotonic() + timeout_s
    while True:
        last_status = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")["RetrievalStatus"]
        if last_status in _TERMINAL:
            return last_status
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the retrieval reaching a terminal state: the run budget ended first; not graded")
            raise AssertionError(f"retrieval never reached a terminal state within {timeout_s}s (last={last_status!r})")
        time.sleep(interval_s)


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


def _ensure_transaction_search_enabled(ctx, xray, timeout_s: float = 600.0) -> None:
    """Grants XRay permission to write to the Transaction Search log groups and
    switches the account's trace segment destination to CloudWatchLogs until cleanup."""
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


def _start_retrieval_with_retry(xray, trace_id, start_time, end_time, *, timeout_s: float, interval_s: float = 2.0,
                                ctx=None) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = xray.start_trace_retrieval(TraceIds=[trace_id], StartTime=start_time, EndTime=end_time)
            return resp["RetrievalToken"]
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("StartTraceRetrieval accepting the ingested trace: the run budget ended first; not graded")
    raise AssertionError(
        f"StartTraceRetrieval never accepted the ingested trace ID within {timeout_s}s (last error: {last_code})"
    )


def _best_effort_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _mutate_token(token: str) -> str:
    """Flip the middle character of a RetrievalToken within its base64url alphabet, keeping
    length and charset so only the token's integrity check can reject it."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    mid = len(token) // 2
    original_char = token[mid]
    replacement = next(c for c in alphabet if c != original_char)
    return token[:mid] + replacement + token[mid + 1 :]


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want` until cleanup; return the original.

    The destination is one setting per account and region and a switch takes minutes to settle."""
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
    # Restore is registered before the switch so a refused or unsettled switch is still undone;
    # a destination left on CloudWatchLogs makes GetTraceSummaries return nothing.
    # The forward switch is bounded by the check's budget; the cleanup restore keeps `timeout_s`.
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
