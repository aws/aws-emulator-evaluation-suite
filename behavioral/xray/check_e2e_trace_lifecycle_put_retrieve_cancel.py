"""e2e-trace-lifecycle-put-retrieve-cancel."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-trace-lifecycle-put-retrieve-cancel"
GROUP = "e2e"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """Enabling Transaction Search (CloudWatchLogs) is refused with an exact AccessDeniedException
    and leaves the destination unchanged; if accepted, a retrieval completes with the trace and a
    cancelled one ends CANCELLED with no traces, or COMPLETE with the trace if the cancel is late."""
    xray = ctx.client("xray")
    logs = ctx.client("logs")

    prior = _settled_trace_segment_destination(xray, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    prior_destination = prior["Destination"]
    ctx.on_cleanup(
        lambda: _restore_trace_segment_destination(xray, prior_destination, timeout_s=600.0)
    )

    # Positive control: PutTraceSegments against the current destination succeeds, so the
    # CloudWatchLogs refusal below is not a symptom of X-Ray being unusable in the account.
    control_now = time.time()
    control_trace_id = f"1-{int(control_now):08x}-{_hex(24)}"
    control_resp = xray.put_trace_segments(
        TraceSegmentDocuments=[
            json.dumps(
                {
                    "name": "sim2ray-lifecycle-control",
                    "id": _hex(16),
                    "trace_id": control_trace_id,
                    "start_time": control_now,
                    "end_time": control_now + 0.05,
                }
            )
        ]
    )
    assert control_resp.get("UnprocessedTraceSegments", []) == [], control_resp

    _ensure_transaction_search_prerequisites(ctx, logs)

    try:
        xray.update_trace_segment_destination(Destination="CloudWatchLogs")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message}"
        assert message == (
            "XRay does not have permission to call PutLogEvents on the aws/spans Log Group. "
            "Please verify that your CloudWatch Logs Resource Policies are configured correctly"
        ), f"unexpected message: {message!r}"
        # Effect-absent: an independent read confirms the destination never moved.
        after = xray.get_trace_segment_destination()
        assert after["Destination"] == prior_destination, after
        return

    _settled_trace_segment_destination(xray, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)

    now = time.time()
    trace_id = f"1-{int(now):08x}-{_hex(24)}"
    seg = {
        "name": "sim2ray-lifecycle-svc",
        "id": _hex(16),
        "trace_id": trace_id,
        "start_time": now,
        "end_time": now + 0.05,
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg)])
    assert put_resp.get("UnprocessedTraceSegments", []) == []

    start_time = now - 300
    end_time_window = now + 300

    token1 = _retry_until_started(xray, trace_id, start_time, end_time_window, timeout_s=_budget_s(ctx, 300), ctx=ctx)
    ctx.on_cleanup(lambda: _best_effort_cancel(xray, token1))

    listed = _poll_until(
        lambda: xray.list_retrieved_traces(RetrievalToken=token1, TraceFormat="XRAY"),
        lambda r: r["RetrievalStatus"] in ("COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"),
        timeout_s=_budget_s(ctx, 240),
        interval_s=1,
        ctx=ctx,
    )
    assert listed["RetrievalStatus"] == "COMPLETE", listed
    trace_ids_seen = {t["Id"] for t in listed.get("Traces", [])}
    assert trace_id in trace_ids_seen, f"expected {trace_id} among retrieved traces: {trace_ids_seen}"

    graph = xray.get_retrieved_traces_graph(RetrievalToken=token1)
    assert graph["RetrievalStatus"] == "COMPLETE"
    assert "Services" in graph

    token2 = _retry_until_started(xray, trace_id, start_time, end_time_window, timeout_s=_budget_s(ctx, 120), ctx=ctx)
    xray.cancel_trace_retrieval(RetrievalToken=token2)

    cancelled = _poll_until(
        lambda: xray.list_retrieved_traces(RetrievalToken=token2, TraceFormat="XRAY"),
        lambda r: r["RetrievalStatus"] in ("CANCELLED", "COMPLETE", "FAILED", "TIMEOUT"),
        timeout_s=_budget_s(ctx, 120),
        interval_s=0.5,
        ctx=ctx,
    )
    # A one-trace retrieval can finish before the cancel reaches it; both outcomes are valid.
    final_status = cancelled["RetrievalStatus"]
    assert final_status in ("CANCELLED", "COMPLETE"), cancelled
    cancelled_ids = {t["Id"] for t in cancelled.get("Traces", [])}
    if final_status == "CANCELLED":
        assert cancelled_ids == set(), f"cancelled retrieval returned traces {cancelled_ids}"
    else:
        assert trace_id in cancelled_ids, (
            f"retrieval that completed before its cancel lacks {trace_id}: {cancelled_ids}"
        )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _ensure_transaction_search_prerequisites(ctx, logs) -> None:
    """Puts the documented CloudWatch Logs resource policy letting X-Ray write to 'aws/spans'.

    The policy is account-global, so cleanup deletes it; 'aws/' log groups are AWS-reserved.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "TransactionSearchXRayAccess",
                    "Effect": "Allow",
                    "Principal": {"Service": "xray.amazonaws.com"},
                    "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                    "Resource": f"arn:aws:logs:{ctx.region}:{account}:log-group:aws/spans:*",
                    "Condition": {
                        "ArnLike": {"aws:SourceArn": f"arn:aws:xray:{ctx.region}:{account}:*"},
                        "StringEquals": {"aws:SourceAccount": account},
                    },
                }
            ],
        }
    )
    logs.put_resource_policy(
        policyName="sim2real-xray-transaction-search", policyDocument=policy_document
    )
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(logs, "sim2real-xray-transaction-search"))


def _safe_delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError("the retrieval reaching a terminal status: the run budget ended first; not graded")
            raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")
        time.sleep(interval_s)


def _retry_until_started(xray, trace_id, start_time, end_time, timeout_s: float, ctx=None) -> str:
    """StartTraceRetrieval 404s (ResourceNotFoundException) until the span has
    been ingested into the Transaction Search log group; retry until it
    succeeds or the timeout elapses.
    """
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = xray.start_trace_retrieval(
                TraceIds=[trace_id], StartTime=start_time, EndTime=end_time
            )
            return resp["RetrievalToken"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                last_exc = exc
                time.sleep(1)
                continue
            raise
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"trace {trace_id} becoming retrievable: the run budget ended first; not graded")
    raise AssertionError(f"trace {trace_id} never became retrievable: {last_exc}")


def _best_effort_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    """Restores the destination and waits until it is ACTIVE, so no PENDING switch is left behind."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
