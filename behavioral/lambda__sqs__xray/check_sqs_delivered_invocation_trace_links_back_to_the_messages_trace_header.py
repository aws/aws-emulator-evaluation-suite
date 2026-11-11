"""sqs-delivered-invocation-trace-links-back-to-the-messages-trace-header."""

from __future__ import annotations

import io
import json
import os
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-delivered-invocation-trace-links-back-to-the-messages-trace-header"
GROUP = "distributed-tracing"
SERVICES = ["lambda", "sqs", "xray"]

HANDLER = "def handler(event, context):\n    return {'records': len(event.get('Records', []))}\n"

_ROLE_PROPAGATION = "cannot be assumed by Lambda"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An SQS event source delivery to a TracingConfig Active function links its own invocation
    trace back to the message's AWSTraceHeader with a parent reference, and two messages with two
    distinct, caller-chosen trace ids each link back to their own and not the other's.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html
    Reference: https://docs.aws.amazon.com/xray/latest/api/API_BatchGetTraces.html
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    xray = ctx.client("xray")

    queue_name = ctx.unique_name("sim2real-behav-sqsxray-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, Attributes={"VisibilityTimeout": "60"},
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=queue_url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"],
    )["Attributes"]["QueueArn"]

    role_arn = _make_role(ctx, ctx.client("iam"), queue_arn)
    fn = _create_function(
        ctx, lam,
        FunctionName=ctx.unique_name("sim2real-behav-sqsxray-"),
        Runtime="python3.13", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.py", HANDLER)}, MemorySize=128, Timeout=10,
        TracingConfig={"Mode": "Active"}, Tags={"sim2real": CHECK},
    )

    esm_id = _create_event_source_mapping(ctx, lam, queue_arn, fn)
    _poll_until(
        ctx,
        lambda: lam.get_event_source_mapping(UUID=esm_id)["State"],
        lambda state: state == "Enabled",
        timeout_s=90.0, description=f"event source mapping {esm_id!r} Enabled",
    )

    seen_trace_ids: set[str] = set()
    for label, body in (("a", "sim2real-a"), ("b", "sim2real-b")):
        root, header = _trace_header()
        started = time.time() - 5
        sqs.send_message(
            QueueUrl=queue_url, MessageBody=body,
            MessageSystemAttributes={
                "AWSTraceHeader": {"DataType": "String", "StringValue": header},
            },
        )
        linked = _poll_until(
            ctx,
            lambda r=root: _segments_linked_to(xray, started, fn, r),
            lambda segs: bool(segs),
            timeout_s=120.0,
            description=(
                f"message {label!r}'s delivery to {fn!r} to produce a segment linking back to "
                f"trace {root!r} (from AWSTraceHeader {header!r})"
            ),
        )
        new_trace_ids = {seg["trace_id"] for seg in linked}
        assert len(new_trace_ids) == 1, (
            f"message {label!r}'s linked segments disagree on trace_id: {new_trace_ids!r}"
        )
        (new_trace_id,) = new_trace_ids
        assert new_trace_id != root, (
            f"message {label!r}'s delivery was filed under the message's own trace id {root!r} "
            "rather than a new trace Lambda links back to it"
        )
        assert new_trace_id not in seen_trace_ids, (
            f"message {label!r} reused trace {new_trace_id!r} from an earlier delivery"
        )
        seen_trace_ids.add(new_trace_id)
        for seg in linked:
            assert seg.get("name") == fn, (
                f"a linked segment for message {label!r} names {seg.get('name')!r}, expected {fn!r}"
            )
            refs = {link["trace_id"]: link.get("attributes", {}).get(
                "aws.xray.reserved.reference_type") for link in seg["links"]}
            assert refs == {root: "parent"}, (
                f"message {label!r}'s segment {seg.get('origin')!r} links are {refs!r}; expected "
                f"to link ONLY to its own trace {root!r}, as 'parent', and not the other message's"
            )


# ===== helpers =====


def _summary_ids(xray, start: float, function_name: str) -> set:
    kwargs: dict = {
        "StartTime": start, "EndTime": time.time() + 5,
        "FilterExpression": f'service("{function_name}")',
    }
    ids: set = set()
    token = None
    while True:
        if token:
            kwargs["NextToken"] = token
        resp = xray.get_trace_summaries(**kwargs)
        ids.update(s["Id"] for s in resp.get("TraceSummaries") or [])
        token = resp.get("NextToken")
        if not token:
            return ids


def _segments_linked_to(xray, start: float, function_name: str, root: str) -> list[dict]:
    """Every segment of ``function_name``'s recent traces that carries a ``links`` entry naming
    ``root`` — however many segments X-Ray recorded for the invocation."""
    ids = _summary_ids(xray, start, function_name)
    if not ids:
        return []
    traces = xray.batch_get_traces(TraceIds=sorted(ids))["Traces"]
    segs = [json.loads(s["Document"]) for t in traces for s in t["Segments"]]
    return [d for d in segs if any(link.get("trace_id") == root for link in d.get("links") or [])]


def _trace_header() -> tuple[str, str]:
    """A fresh ``(root_id, "Root=...;Parent=...;Sampled=1")`` an upstream producer might send."""
    root = f"1-{int(time.time()):08x}-{os.urandom(12).hex()}"
    parent = os.urandom(8).hex()
    return root, f"Root={root};Parent={parent};Sampled=1"


def _zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s: float, interval_s: float = 2.0, description: str):
    """Bounded retry on an observable condition. RAISES on timeout, never returns its last value."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _make_role(ctx, iam, queue_arn: str) -> str:
    """This check's own execution role: SQS polling + xray:PutTraceSegments, no logs grant."""
    name = ctx.unique_name("sim2real-behav-sqsxray-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    statements = [
        {"Effect": "Allow",
         "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
         "Resource": queue_arn},
        {"Effect": "Allow",
         "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], "Resource": "*"},
    ]
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity",
    ))
    # IAM propagation exposes no pollable condition; the bounded role-propagation retries at
    # CreateFunction and CreateEventSourceMapping are what make first use correct.
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs) -> str:
    """CreateFunction retrying ONLY the documented role-propagation refusal; waits for Active.

    No logs permission is granted to this function's role, so Lambda never creates its
    /aws/lambda/<fn> log group and there is nothing to reap.
    """
    name = kwargs["FunctionName"]
    timeout_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            code = exc.response["Error"]["Code"]
            if code != "InvalidParameterValueException" or _ROLE_PROPAGATION not in msg:
                raise
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"CreateFunction({name}): the run budget ended first; not graded") from exc
                raise AssertionError(f"CreateFunction({name}) kept failing on role propagation: {msg}") from exc
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    _wait_ready(ctx, lam, name)
    return name


def _wait_ready(ctx, lam, name: str) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(f"{name} failed: {cfg.get('StateReason')}")
        return cfg

    return _poll_until(
        ctx, _probe,
        lambda cfg: cfg.get("State") == "Active"
        and cfg.get("LastUpdateStatus") in (None, "Successful"),
        timeout_s=180.0, description=f"{name} Active + LastUpdateStatus=Successful",
    )


def _create_event_source_mapping(ctx, lam, queue_arn: str, fn: str) -> str:
    """CreateEventSourceMapping retrying ONLY the documented role-propagation refusal."""
    timeout_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = lam.create_event_source_mapping(
                EventSourceArn=queue_arn, FunctionName=fn, Enabled=True, BatchSize=1,
            )
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            code = exc.response["Error"]["Code"]
            propagating = code == "InvalidParameterValueException" and (
                "cannot be assumed" in msg or "does not have permission" in msg
            )
            if not propagating:
                raise
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"CreateEventSourceMapping({fn}): the run budget ended first; not graded") from exc
                raise
            time.sleep(3)
    esm_id = resp["UUID"]
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_event_source_mapping(UUID=esm_id), "ResourceNotFoundException",
    ))
    return esm_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
