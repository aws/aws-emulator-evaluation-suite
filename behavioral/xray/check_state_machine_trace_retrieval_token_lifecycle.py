"""state-machine-trace-retrieval-token-lifecycle."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "state-machine-trace-retrieval-token-lifecycle"
GROUP = "state-machine"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """A cancelled RetrievalToken stays readable: ListRetrievedTraces and GetRetrievedTracesGraph
    both report CANCELLED with no traces or segment service, while a never-cancelled token reaches
    COMPLETE in both reads, so the status tracks the token rather than being fixed."""
    xray = ctx.client("xray")
    _enable_transaction_search(ctx, xray)
    ingest_timeout = 300
    terminal_timeout = 300

    # Token A is cancelled immediately so the cancel wins the race against completion; a job
    # that finished first refuses the cancel, so a fresh retrieval is started and cancelled.
    trace_id_a, seg_a, start_a, end_a = _build_segment(ctx)
    xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg_a)])
    cancel_deadline = time.monotonic() + _budget_s(ctx, ingest_timeout)
    while True:
        token_a = _start_retrieval_with_retry(
            ctx, xray, [trace_id_a], start_a - 300, end_a + 300,
            max(1.0, cancel_deadline - time.monotonic()),
        )
        try:
            xray.cancel_trace_retrieval(RetrievalToken=token_a)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            if time.monotonic() >= cancel_deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("a cancel racing a running retrieval: the run budget ended first; "
                                       "not graded") from exc
                raise AssertionError(
                    "every retrieval reached a terminal state before cancellation could race "
                    "it; timing was too tight in this run to observe the CANCELLED transition"
                ) from exc
            time.sleep(1.0)

    cancelled_list = xray.list_retrieved_traces(RetrievalToken=token_a, TraceFormat="XRAY")
    assert cancelled_list["RetrievalStatus"] == "CANCELLED", (
        f"ListRetrievedTraces on a cancelled token reported status="
        f"{cancelled_list['RetrievalStatus']!r} instead of CANCELLED"
    )
    assert not cancelled_list.get("Traces"), (
        "ListRetrievedTraces on a cancelled token unexpectedly returned traces: "
        f"{cancelled_list.get('Traces')!r}"
    )
    cancelled_graph = xray.get_retrieved_traces_graph(RetrievalToken=token_a)
    assert cancelled_graph["RetrievalStatus"] == "CANCELLED", (
        f"GetRetrievedTracesGraph on a cancelled token reported status="
        f"{cancelled_graph['RetrievalStatus']!r} instead of CANCELLED"
    )
    cancelled_services = _service_names(cancelled_graph)
    assert seg_a["name"] not in cancelled_services, (
        f"GetRetrievedTracesGraph on a cancelled token surfaced the submitted segment's own "
        f"service {seg_a['name']!r} among {cancelled_services}, as if the retrieval had "
        "completed despite being cancelled"
    )

    trace_id_b, seg_b, start_b, end_b = _build_segment(ctx)
    xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg_b)])
    token_b = _start_retrieval_with_retry(
        ctx, xray, [trace_id_b], start_b - 300, end_b + 300, _budget_s(ctx, ingest_timeout)
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(xray, token_b))
    control_status = _poll_until_terminal(xray, token_b, _budget_s(ctx, terminal_timeout), ctx=ctx)
    assert control_status == "COMPLETE", (
        f"positive-control token unexpectedly reported terminal status {control_status!r} "
        "instead of COMPLETE"
    )
    # Only RetrievalStatus is asserted: the graph's Services can lag or stay empty even when COMPLETE.
    control_graph = xray.get_retrieved_traces_graph(RetrievalToken=token_b)
    assert control_graph["RetrievalStatus"] == "COMPLETE", (
        "GetRetrievedTracesGraph on the un-cancelled control disagreed with ListRetrievedTraces "
        f"about the retrieval's terminal status: got {control_graph['RetrievalStatus']!r}"
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
    return "".join(random.choices("0123456789abcdef", k=n))


def _build_segment(ctx):
    now = time.time()
    start_time = now - 5
    end_time = now
    trace_id = f"1-{format(int(now), 'x')}-{_hex(24)}"
    segment_id = _hex(16)
    name = ctx.unique_name("sim2real-behav-xrtl-")
    doc = {
        "trace_id": trace_id,
        "id": segment_id,
        "name": name,
        "start_time": start_time,
        "end_time": end_time,
    }
    return trace_id, doc, start_time, end_time


def _enable_transaction_search(ctx, xray) -> None:
    _ensure_transaction_search_resource_policy(ctx, xray)
    _pin_trace_segment_destination(ctx, "CloudWatchLogs", timeout_s=600.0)


def _ensure_transaction_search_resource_policy(ctx, xray) -> None:
    # UpdateTraceSegmentDestination(CloudWatchLogs) is denied until xray.amazonaws.com holds
    # logs:PutLogEvents on the destination log groups.
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


def _start_retrieval_with_retry(ctx, xray, trace_ids, start_time, end_time, timeout_s):
    interval_s = 2
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
    if _budget_spent(ctx):
        raise TimeoutError("Transaction Search surfacing the ingested trace: the run budget ended first; not graded")
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


def _service_names(graph) -> set:
    return {s.get("Service", {}).get("Name") for s in graph.get("Services", [])}


_TERMINAL = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}


def _poll_until_terminal(xray, token, timeout_s, interval_s=1, ctx=None) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")[
            "RetrievalStatus"
        ]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"retrieval {token} reaching a terminal state: the run budget ended first; not graded")
    raise AssertionError(f"retrieval {token} never reached a terminal state (last={status})")


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
