"""cancel-trace-retrieval-unknown-token-fails."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-trace-retrieval-unknown-token-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """CancelTraceRetrieval moves a real active retrieval to CANCELLED, and fails with
    InvalidRequestException and a message naming the token for a never-issued RetrievalToken.
    """
    xr = ctx.client("xray")
    logs = ctx.client("logs")
    sts = ctx.client("sts")

    _ensure_transaction_search_enabled(ctx, xr, logs, sts)

    now = time.time()
    trace_id = _make_trace_id(now)
    segment = {
        "trace_id": trace_id,
        "id": _make_segment_id(),
        "name": ctx.unique_name("sim2real-xray-behav-"),
        "start_time": now - 2,
        "end_time": now - 1,
    }
    put_resp = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    window_start = now - 600
    window_end = now + 600

    def _start_retrieval():
        try:
            return xr.start_trace_retrieval(
                TraceIds=[trace_id], StartTime=window_start, EndTime=window_end
            )["RetrievalToken"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise

    real_token = _poll_until(
        _start_retrieval, lambda t: t is not None, timeout_s=600.0, interval_s=8.0
    )
    ctx.on_cleanup(lambda: _safe_cancel(xr, real_token))

    # Positive control: cancelling a real, just-issued token succeeds and moves it to
    # CANCELLED -- proving the rejection below is specific to the bad token, not a sign
    # CancelTraceRetrieval is rejected outright for this account.
    xr.cancel_trace_retrieval(RetrievalToken=real_token)  # must not raise
    cancelled_status = xr.list_retrieved_traces(RetrievalToken=real_token, TraceFormat="XRAY")[
        "RetrievalStatus"
    ]
    assert cancelled_status == "CANCELLED", (
        f"cancelling a real, active RetrievalToken did not reach CANCELLED: {cancelled_status}"
    )

    bad_token = "sim2real-behav-not-a-real-token"
    error = _client_error(lambda: xr.cancel_trace_retrieval(RetrievalToken=bad_token))
    assert error.get("Code") == "InvalidRequestException", (
        f"expected InvalidRequestException, got {error!r}"
    )
    assert error.get("Message") == (
        f"Invalid retrieval token {bad_token} passed: Invalid Execution Id"
    ), f"the refusal must name the rejected token, got {error!r}"


def _ensure_transaction_search_enabled(ctx, xr, logs, sts) -> None:
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    policy_name = ctx.unique_name("sim2real-xray-txsearch-policy-")
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
    # This is a CloudWatch Logs resource policy (grants xray.amazonaws.com permission to
    # write into the aws/spans log group), not an X-Ray resource policy -- xray's own
    # PutResourcePolicy grants OTHER principals access to call X-Ray APIs and rejects this
    # document as malformed.
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: logs.delete_resource_policy(policyName=policy_name))

    _pin_trace_segment_destination(ctx, "CloudWatchLogs")


def _make_trace_id(now: float) -> str:
    epoch = format(int(now), "x")[-8:].rjust(8, "0")
    rand = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return f"1-{epoch}-{rand}"


def _make_segment_id() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


def _safe_cancel(xr, token: str) -> None:
    try:
        xr.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
