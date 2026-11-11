"""start-trace-retrieval-consistent-token-data-plane."""
from __future__ import annotations

import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-trace-retrieval-consistent-token-data-plane"
GROUP = "data-plane"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """StartTraceRetrieval returns a RetrievalToken that both ListRetrievedTraces and
    GetRetrievedTracesGraph accept for the same retrieval session, and the two APIs track
    one consistent RetrievalStatus lifecycle rather than diverging job states."""
    xray = ctx.client("xray")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    _ensure_transaction_search_enabled(ctx, xray, account_id, region)

    trace_id = _make_trace_id()
    segment_id = _make_segment_id()
    now = time.time()
    document = {
        "trace_id": trace_id,
        "id": segment_id,
        "name": ctx.unique_name("sim2real-xray-behav"),
        "start_time": now,
        "end_time": now + 0.05,
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(document)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment {segment_id!r} was rejected: {put_resp.get('UnprocessedTraceSegments')!r}"
    )

    start_time = now - 60
    end_time = now + 600

    token = _poll_for_retrieval_token(ctx, trace_id, start_time, end_time, timeout_s=600.0)
    ctx.on_cleanup(lambda: _safe_cancel(ctx, token))

    # A just-started retrieval has not failed: both APIs read it as SCHEDULED, RUNNING or COMPLETE
    # (a one-trace job can finish within the round trip).
    started = ("SCHEDULED", "RUNNING", "COMPLETE")
    list_status_1 = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")["RetrievalStatus"]
    graph_status_1 = xray.get_retrieved_traces_graph(RetrievalToken=token)["RetrievalStatus"]
    assert list_status_1 in started, (
        f"ListRetrievedTraces returned RetrievalStatus {list_status_1!r} for the just-started "
        f"token {token!r}, expected one of {started}"
    )
    assert graph_status_1 in started, (
        f"GetRetrievedTracesGraph returned RetrievalStatus {graph_status_1!r} for the just-started "
        f"token {token!r}, expected one of {started}"
    )

    terminal = {"COMPLETE", "FAILED", "CANCELLED", "TIMEOUT"}

    def _probe():
        list_status = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")["RetrievalStatus"]
        graph_status = xray.get_retrieved_traces_graph(RetrievalToken=token)["RetrievalStatus"]
        return (list_status, graph_status)

    final_list_status, final_graph_status = _poll_until(
        _probe,
        lambda pair: pair[0] in terminal and pair[1] in terminal,
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final_list_status == final_graph_status, (
        f"ListRetrievedTraces reported {final_list_status!r} but GetRetrievedTracesGraph reported "
        f"{final_graph_status!r} for the same RetrievalToken {token!r}"
    )


def _ensure_transaction_search_enabled(ctx, xray, account_id: str, region: str) -> None:
    """CloudWatch Logs' own resource policy (not XRay's PutResourcePolicy, which is a
    different API for a different purpose and answers MalformedPolicyDocumentException
    for this document shape) must grant XRay logs:PutLogEvents on the aws/spans log
    group before UpdateTraceSegmentDestination(CloudWatchLogs) can take effect — without
    it, real AWS answers AccessDeniedException. Idempotent: only flips the account-global
    destination when it is not already CloudWatchLogs, and always restores what it found."""
    logs = ctx.client("logs")
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
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: logs.delete_resource_policy(policyName=policy_name))

    _pin_trace_segment_destination(ctx, "CloudWatchLogs")


def _make_trace_id() -> str:
    return f"1-{int(time.time()):08x}-{os.urandom(12).hex()}"


def _make_segment_id() -> str:
    return os.urandom(8).hex()


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={last!r}")


def _poll_for_retrieval_token(ctx, trace_id: str, start_time: float, end_time: float, timeout_s: float = 600.0):
    xray = ctx.client("xray")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = xray.start_trace_retrieval(TraceIds=[trace_id], StartTime=start_time, EndTime=end_time)
            return resp["RetrievalToken"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            last_err = exc
            if code != "ResourceNotFoundException":
                raise
        time.sleep(2.0)
    raise AssertionError(
        f"trace {trace_id} never became retrievable via StartTraceRetrieval within {timeout_s}s: {last_err}"
    )


def _safe_cancel(ctx, token: str) -> None:
    xray = ctx.client("xray")
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
            time.sleep(2.0)
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
