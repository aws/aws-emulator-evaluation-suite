"""e2e-trace-retrieval-full-flow."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "e2e-trace-retrieval-full-flow"
GROUP = "e2e"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """With Transaction Search on, a written segment comes back through StartTraceRetrieval,
    ListRetrievedTraces and GetRetrievedTracesGraph; cancelling a COMPLETE retrieval leaves it
    COMPLETE, cancelling a just-started one makes it CANCELLED."""
    xray = ctx.client("xray")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    _ensure_transaction_search_enabled(ctx, xray, logs, account_id, region)

    now = time.time()
    trace_id = _make_trace_id()
    svc_name = ctx.unique_name("sim2real-xray-retrieval-svc-")
    segment = {
        "trace_id": trace_id,
        "id": _make_segment_id(),
        "name": svc_name,
        "start_time": now - 2,
        "end_time": now - 1,
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    window_start = now - 600
    window_end = now + 600

    def _start_retrieval():
        from botocore.exceptions import ClientError

        try:
            return xray.start_trace_retrieval(
                TraceIds=[trace_id], StartTime=window_start, EndTime=window_end
            )["RetrievalToken"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise

    def _attempt_retrieval():
        # Indexing latency into the Transaction Search log group shows up two
        # ways: StartTraceRetrieval can 404 outright (handled by the inner poll
        # below), or it can accept the request and complete a job that simply
        # found nothing yet. Either way the fix is the same -- start a fresh job
        # and try again, which the outer poll does by discarding a non-matching
        # attempt and calling this probe again.
        job_token = _poll_until(
            _start_retrieval,
            lambda t: t is not None,
            timeout_s=180.0,
            interval_s=15.0,
        )
        job_listed = _poll_until(
            lambda: xray.list_retrieved_traces(RetrievalToken=job_token, TraceFormat="XRAY"),
            lambda resp: resp["RetrievalStatus"] in ("COMPLETE", "FAILED", "TIMEOUT"),
            timeout_s=240.0,
            interval_s=10.0,
        )
        return job_token, job_listed

    token, listed = _poll_until(
        _attempt_retrieval,
        lambda result: result[1]["RetrievalStatus"] == "COMPLETE"
        and any(t["Id"] == trace_id for t in result[1].get("Traces", [])),
        timeout_s=600.0,
        interval_s=20.0,
    )
    assert listed["RetrievalStatus"] == "COMPLETE", (
        f"retrieval did not complete: {listed['RetrievalStatus']}"
    )
    traces = listed.get("Traces", [])
    assert any(t["Id"] == trace_id for t in traces), (
        f"written trace {trace_id} was not among the retrieved traces: {traces}"
    )
    matched = next(t for t in traces if t["Id"] == trace_id)
    assert matched.get("Spans"), "retrieved trace had no spans"

    graph = xray.get_retrieved_traces_graph(RetrievalToken=token)
    assert graph["RetrievalStatus"] == "COMPLETE", (
        f"expected the service graph retrieval to be COMPLETE, got {graph['RetrievalStatus']!r}"
    )
    service_names = {s["Service"]["Name"] for s in graph.get("Services", []) if s.get("Service")}
    assert svc_name in service_names, (
        f"retrieved traces graph did not include our service {svc_name}: {service_names}"
    )

    # Cancelling a retrieval that has already reached COMPLETE succeeds as a no-op (HTTP 200)
    # and must not flip the job's recorded status to CANCELLED.
    xray.cancel_trace_retrieval(RetrievalToken=token)  # must not raise
    still = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
    assert still["RetrievalStatus"] == "COMPLETE", (
        f"cancelling an already-completed retrieval mutated its status to {still['RetrievalStatus']!r}"
    )

    # Positive control: cancelling a retrieval immediately after starting it --
    # before it has had time to reach a terminal state -- succeeds and actually
    # moves it to CANCELLED. Without this, a target whose CancelTraceRetrieval is
    # a permanent no-op (never cancelling anything) would also pass the
    # completed-retrieval no-op assertion above.
    racing_token = xray.start_trace_retrieval(
        TraceIds=[trace_id], StartTime=window_start, EndTime=window_end
    )["RetrievalToken"]
    xray.cancel_trace_retrieval(RetrievalToken=racing_token)  # must not raise
    raced_status = xray.list_retrieved_traces(RetrievalToken=racing_token, TraceFormat="XRAY")[
        "RetrievalStatus"
    ]
    assert raced_status == "CANCELLED", (
        f"expected cancelling a just-started retrieval to move it to CANCELLED, got {raced_status!r}"
    )


def _ensure_transaction_search_enabled(ctx, xray, logs, account_id: str, region: str) -> None:
    # The CloudWatch Logs delivery permission for Transaction Search is a Logs
    # resource policy (logs:PutResourcePolicy), not an X-Ray one -- xray.PutResourcePolicy
    # governs cross-account access to the X-Ray API surface itself and rejects this
    # document with MalformedPolicyDocumentException.
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
    logs.put_resource_policy(
        policyName=policy_name,
        policyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(lambda: logs.delete_resource_policy(policyName=policy_name))

    _pin_trace_segment_destination(ctx, "CloudWatchLogs")


def _make_trace_id() -> str:
    epoch = format(int(time.time()), "x")[-8:].rjust(8, "0")
    rand = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return f"1-{epoch}-{rand}"


def _make_segment_id() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


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

    The destination (XRay, or CloudWatchLogs for Transaction Search) is one setting per account
    and region, and a switch takes about 6 minutes to go PENDING -> ACTIVE. The original is read
    first and its restore registered before the switch, so a refused or unsettled switch is undone."""
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
