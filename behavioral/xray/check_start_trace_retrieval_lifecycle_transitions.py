"""start-trace-retrieval-lifecycle-transitions."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-trace-retrieval-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["xray"]

_TERMINAL = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """A trace retrieval reaches COMPLETE via ListRetrievedTraces and GetRetrievedTracesGraph with
    the submitted segment's service in its graph, and one cancelled while running ends CANCELLED
    with no traces."""
    xray = ctx.client("xray")
    _grant_transaction_search_delivery(ctx)
    _pin_trace_segment_destination(ctx, "CloudWatchLogs")

    trace_id, service_name, seg_start, seg_end = _put_indexed_segment(ctx, xray)
    window_start = seg_start - 300
    window_end = seg_end + 300

    token = _completed_retrieval_with_trace(ctx, xray, trace_id, window_start, window_end)

    graph = xray.get_retrieved_traces_graph(RetrievalToken=token)
    assert graph["RetrievalStatus"] == "COMPLETE", (
        f"expected the independent graph read to agree the retrieval is COMPLETE, "
        f"got {graph['RetrievalStatus']}"
    )
    services = graph.get("Services", [])
    assert isinstance(services, list) and services, (
        "GetRetrievedTracesGraph returned no services for a COMPLETE retrieval "
        "that covers a real, submitted segment"
    )
    names = {s.get("Service", {}).get("Name") for s in services}
    assert service_name in names, (
        f"expected the submitted segment's service {service_name!r} to appear in the "
        f"completed retrieval's graph, got services named {names}"
    )

    outcomes = _cancel_until_cancelled(ctx, xray, trace_id, window_start, window_end)
    assert outcomes[-1] == ("CANCELLED", set()), f"cancel attempts: {outcomes}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _put_indexed_segment(ctx, xray):
    """Put a real segment; return (trace_id, service_name, start_time, end_time).

    StartTraceRetrieval rejects an empty TraceIds list ('Zero trace ids provided')."""
    now = datetime.now(timezone.utc)
    start_time = now.timestamp()
    end_time = start_time + 0.25
    trace_id = f"1-{int(start_time):08x}-{random.getrandbits(96):024x}"
    segment_id = f"{random.getrandbits(64):016x}"
    service_name = ctx.unique_name("sim2real-behav-strlt-")
    doc = {
        "name": service_name,
        "id": segment_id,
        "trace_id": trace_id,
        "start_time": start_time,
        "end_time": end_time,
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(doc)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment was rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )
    return trace_id, service_name, start_time, end_time


def _start_retrieval_once_indexed(xray, trace_id, start_time, end_time, *, timeout_s, interval_s, ctx=None):
    """Retry StartTraceRetrieval past ResourceNotFoundException until Transaction Search has
    indexed the segment."""
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


def _completed_retrieval_with_trace(ctx, xray, trace_id, start_time, end_time, *, timeout_s=600.0):
    """-> the token of a COMPLETE retrieval that returned `trace_id`.

    A job started before the spans are indexed completes empty, so fresh jobs are started."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        token = _start_retrieval_once_indexed(
            xray, trace_id, start_time, end_time, timeout_s=_budget_s(ctx, 180.0), interval_s=1.0, ctx=ctx
        )
        ctx.on_cleanup(lambda t=token: _best_effort_cancel(xray, t))
        status = _poll_retrieval_status(xray, token, timeout_s=_budget_s(ctx, 300), interval_s=0.5, ctx=ctx)
        assert status == "COMPLETE", f"expected COMPLETE, got {status}"
        ids = _retrieved_trace_ids(xray, token)
        if ids == {trace_id}:
            return token
        assert ids == set(), f"retrieval of {trace_id!r} returned other traces {ids}"
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"a COMPLETE retrieval returning {trace_id!r}: the run budget ended first; "
                                   "not graded")
            raise AssertionError(
                f"no COMPLETE retrieval returned the submitted trace {trace_id!r} within "
                f"{timeout_s:.0f}s"
            )
        time.sleep(1.0)


def _retrieved_trace_ids(xray, token: str) -> set:
    resp = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
    return {t.get("Id") for t in resp.get("Traces", [])}


def _cancel_until_cancelled(ctx, xray, trace_id, start_time, end_time, *, attempts: int = 20):
    """Start and cancel retrievals until one is cancelled while running; -> [(status, trace ids)].

    A one-trace retrieval finishes in under a second, so a late cancel leaves it COMPLETE."""
    outcomes = []
    for _ in range(attempts):
        token = xray.start_trace_retrieval(
            TraceIds=[trace_id], StartTime=start_time, EndTime=end_time
        )["RetrievalToken"]
        ctx.on_cleanup(lambda t=token: _best_effort_cancel(xray, t))
        xray.cancel_trace_retrieval(RetrievalToken=token)
        status = _poll_retrieval_status(xray, token, timeout_s=_budget_s(ctx, 60.0), interval_s=0.5, ctx=ctx)
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


def _best_effort_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
