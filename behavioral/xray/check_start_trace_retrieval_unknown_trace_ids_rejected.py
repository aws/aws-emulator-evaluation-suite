"""start-trace-retrieval-unknown-trace-ids-rejected."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-trace-retrieval-unknown-trace-ids-rejected"
GROUP = "error-semantics"
SERVICES = ["xray"]

_TERMINAL = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """StartTraceRetrieval accepts never-ingested trace IDs and omits them from the COMPLETE
    ListRetrievedTraces result beside a real trace, yet rejects the same IDs with a reversed time
    range with InvalidRequestException: it validates the range, never trace-ID existence."""
    xray = ctx.client("xray")
    _ensure_transaction_search_enabled(ctx, xray)
    real_trace_id = _put_real_trace_segment(ctx, xray)

    unknown_trace_ids = [_fake_trace_id(), _fake_trace_id_2()]

    # Transaction Search indexing lags submission by minutes, and a job that finished before
    # indexing caught up never revisits its results, so a fresh job is started each retry.
    seen_ids = _await_real_trace_retrievable(
        ctx, xray, real_trace_id, unknown_trace_ids, timeout_s=900.0, interval_s=2.0
    )
    clashing = set(unknown_trace_ids) & seen_ids
    assert not clashing, (
        f"unknown trace IDs unexpectedly materialized in the completed retrieval: {clashing}"
    )

    now = datetime.now(timezone.utc)
    code_other, message_other = _error_code(
        lambda: xray.start_trace_retrieval(
            TraceIds=unknown_trace_ids, StartTime=now, EndTime=now - timedelta(hours=1)
        )
    )
    assert code_other == "InvalidRequestException", (
        f"expected InvalidRequestException for the reversed time range, got {code_other}"
    )
    expected_message = (
        "Input parameters invalid for request. End time cannot be earlier than start time"
    )
    assert message_other == expected_message, (
        f"expected message {expected_message!r}, got {message_other!r}"
    )


# ===== helpers =====
def _fake_trace_id() -> str:
    return "1-5f84c7a1-a1b2c3d4e5f60718293a4b5c"


def _fake_trace_id_2() -> str:
    return "1-63aa11bb-0c1d2e3f4a5b6c7d8e9fa0b1"


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return the ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _make_trace_id() -> str:
    return f"1-{int(time.time()):08x}-{os.urandom(12).hex()}"


def _put_real_trace_segment(ctx, xray) -> str:
    now = time.time()
    trace_id = _make_trace_id()
    segment = {
        "id": os.urandom(8).hex(),
        "trace_id": trace_id,
        "name": ctx.unique_name("sim2real-xray-unknown-ids-"),
        "start_time": now - 1.0,
        "end_time": now,
    }
    resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment submission rejected: {resp.get('UnprocessedTraceSegments')}"
    )
    return trace_id


def _poll_until_terminal(xray, token: str, *, timeout_s: float, interval_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        last = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
        if last.get("RetrievalStatus") in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"retrieval {token} never reached a terminal state (last={last!r})")


def _await_real_trace_retrievable(
    ctx, xray, real_trace_id: str, unknown_trace_ids: list[str], *, timeout_s: float, interval_s: float
) -> set[str]:
    deadline = time.monotonic() + timeout_s
    last_seen: set[str] = set()
    while time.monotonic() < deadline:
        now = datetime.now(timezone.utc)
        try:
            resp = xray.start_trace_retrieval(
                TraceIds=[real_trace_id, *unknown_trace_ids],
                StartTime=now - timedelta(hours=1),
                EndTime=now,
            )
        except ClientError as exc:
            # Until the first indexed span creates the Transaction Search log group, AWS
            # refuses the retrieval with ResourceNotFoundException ("No log groups were found").
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
            continue
        token = resp["RetrievalToken"]
        listed = _poll_until_terminal(xray, token, timeout_s=180.0, interval_s=2.0)
        if listed.get("RetrievalStatus") == "COMPLETE":
            last_seen = {t["Id"] for t in listed.get("Traces", [])}
            if real_trace_id in last_seen:
                ctx.on_cleanup(lambda t=token: _safe_cancel(xray, t))
                return last_seen
        _safe_cancel(xray, token)
        time.sleep(interval_s)
    raise AssertionError(
        f"real trace {real_trace_id} never appeared in a COMPLETE retrieval within {timeout_s}s "
        f"(last seen: {sorted(last_seen)})"
    )


def _ensure_transaction_search_enabled(ctx, xray, timeout_s: float = 600.0) -> None:
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


def _safe_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
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
