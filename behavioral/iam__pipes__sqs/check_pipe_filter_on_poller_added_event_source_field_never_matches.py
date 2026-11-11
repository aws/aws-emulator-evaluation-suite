"""pipe-filter-on-poller-added-event-source-field-never-matches."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipe-filter-on-poller-added-event-source-field-never-matches"

GROUP = "data-delivery"

SERVICES = ["iam", "pipes", "sqs"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A FilterCriteria pattern on ``eventSource`` -- a field the SQS poller adds, not one the
    source API sent -- matches nothing: the pipe consumes that record and delivers only a later
    record its ORed body clause matches, as a twin body-filter pipe does.
    """
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")

    # --- Twin B: a body-clause filter, which delivers its match and drops the non-match.
    src_b = _create_queue(ctx, VisibilityTimeout="60")
    dst_b = _create_queue(ctx)
    role_b = _create_role(
        ctx, "pipes.amazonaws.com", inline_policy=_sqs_pipe_policy(src_b["arn"], dst_b["arn"]),
    )
    pipe_b = _create_pipe_with_retry(
        pipes,
        Name=_xname(ctx, "pipe-body"),
        RoleArn=role_b["arn"],
        Source=src_b["arn"],
        Target=dst_b["arn"],
        DesiredState="RUNNING",
        SourceParameters={
            "SqsQueueParameters": {"BatchSize": 1},
            "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"body": {"marker": ["match"]}})}]},
        },
        Tags=dict(_MANAGED),
    )
    ctx.on_cleanup(lambda: _delete_pipe(ctx, pipe_b))
    _poll_until(
        lambda: pipes.describe_pipe(Name=pipe_b).get("CurrentState"),
        lambda s: s == "RUNNING",
        timeout_s=240.0,
        interval_s=5.0,
        description=f"pipe {pipe_b} RUNNING",
    )

    nonce = _xname(ctx, "nonce")
    sqs.send_message(QueueUrl=src_b["url"], MessageBody=json.dumps({"marker": "skip", "nonce": nonce}))
    sqs.send_message(QueueUrl=src_b["url"], MessageBody=json.dumps({"marker": "match", "nonce": nonce}))

    matched, others = _wait_for(
        ctx, dst_b["url"], lambda b: _inner(b).get("marker") == "match",
        timeout_s=180.0,
    )
    assert [_inner(b) for b in matched] == [{"marker": "match", "nonce": nonce}], (
        f"control: the body-clause twin pipe must deliver exactly its matching record, got {matched!r}"
    )
    leaked = [b for b in others if _inner(b).get("marker") == "skip"]
    assert leaked == [], (
        f"the body-clause filter let the non-matching record through too: {leaked!r}"
    )

    # --- Pipe A: a filter on eventSource, a field the poller adds and the model documents as
    # unusable in an event pattern, ORed with a body clause that matches only the later control.
    src_a = _create_queue(ctx, VisibilityTimeout="60")
    dst_a = _create_queue(ctx)
    role_a = _create_role(
        ctx, "pipes.amazonaws.com", inline_policy=_sqs_pipe_policy(src_a["arn"], dst_a["arn"]),
    )
    pipe_a = _create_pipe_with_retry(
        pipes,
        Name=_xname(ctx, "pipe-eventsource"),
        RoleArn=role_a["arn"],
        Source=src_a["arn"],
        Target=dst_a["arn"],
        DesiredState="RUNNING",
        SourceParameters={
            "SqsQueueParameters": {"BatchSize": 1},
            "FilterCriteria": {
                "Filters": [
                    {"Pattern": json.dumps({"eventSource": ["aws:sqs"]})},
                    {"Pattern": json.dumps({"body": {"marker": ["ctl"]}})},
                ]
            },
        },
        Tags=dict(_MANAGED),
    )
    ctx.on_cleanup(lambda: _delete_pipe(ctx, pipe_a))
    _poll_until(
        lambda: pipes.describe_pipe(Name=pipe_a).get("CurrentState"),
        lambda s: s == "RUNNING",
        timeout_s=240.0,
        interval_s=5.0,
        description=f"pipe {pipe_a} RUNNING",
    )

    # Every real SQS record's eventSource is literally "aws:sqs" (the value the pattern asks
    # for); a pipe that filtered on it as an ordinary field would deliver every message.
    sqs.send_message(
        QueueUrl=src_a["url"],
        MessageBody=json.dumps({"eventSource": "aws:sqs", "nonce": nonce}),
    )

    # The poller consumes the record it filtered out; only then does the control go in.
    _queue_depth_zero(ctx, src_a["url"], timeout_s=180.0)
    sqs.send_message(QueueUrl=src_a["url"], MessageBody=json.dumps({"marker": "ctl", "nonce": nonce}))

    matched_a, others_a = _wait_for(
        ctx, dst_a["url"], lambda b: _inner(b).get("marker") == "ctl", timeout_s=180.0,
    )
    assert [_inner(b) for b in matched_a] == [{"marker": "ctl", "nonce": nonce}], (
        f"the ORed body clause must deliver exactly the later control record, got {matched_a!r}"
    )
    assert others_a == [], (
        f"a FilterCriteria pattern on eventSource must never match (it is added by the SQS "
        f"poller, not sent by the source API), so only the control may reach the target; "
        f"got {others_a!r}"
    )


# ===== helpers (self-contained) =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"
_MANAGED = {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_resource_tags() -> dict[str, str]:
    return dict(_MANAGED)


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED.items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    url = sqs.create_queue(QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _inner(parsed):
    """The ORIGINAL source body, parsed, out of the SQS record envelope the pipe delivers when
    it carries no InputTemplate (``body`` holds the source message's raw string verbatim)."""
    if isinstance(parsed, dict):
        if isinstance(parsed.get("body"), str):
            try:
                inner = json.loads(parsed["body"])
            except (json.JSONDecodeError, ValueError):
                return {}
            return inner if isinstance(inner, dict) else {}
        return parsed
    return {}


def _wait_for(ctx, queue_url, predicate, *, timeout_s=60.0):
    """Poll a queue until a parsed body satisfies predicate(); returns (matched, others)."""
    matched: list[Any] = []
    others: list[Any] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        sqs = ctx.client("sqs")
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            parsed = _body(msg)
            (matched if predicate(parsed) else others).append(parsed)
    return matched, others


def _queue_depth_zero(ctx, queue_url, *, timeout_s=90.0):
    """Poll until the queue reports zero visible AND zero in-flight messages."""
    sqs = ctx.client("sqs")

    def probe():
        return sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]

    return _poll_until(
        probe,
        lambda a: (
            a.get("ApproximateNumberOfMessages") == "0"
            and a.get("ApproximateNumberOfMessagesNotVisible") == "0"
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"{queue_url} drained to zero",
    )


def _sqs_pipe_policy(source_arn: str, target_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
        ],
    }


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_pipe_with_retry(pipes_client, *, timeout_s: float = 60.0, **kwargs: Any) -> str:
    """create_pipe, retried past IAM role trust/permission propagation lag. Returns the pipe name."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            pipes_client.create_pipe(**kwargs)
            return kwargs["Name"]
        except ClientError as e:
            msg = str(e)
            if (
                "cannot be assumed" in msg
                or "not authorized to perform: iam:PassRole" in msg
                or "ValidationException" in msg
            ):
                last_err = e
                time.sleep(5)
                continue
            raise
    raise AssertionError(
        f"could not create pipe {kwargs.get('Name')!r} within {timeout_s}s (IAM role propagation?): "
        f"{last_err}"
    )


_TRANSITIONAL_PIPE_STATES = ("CREATING", "UPDATING", "STARTING", "STOPPING", "DELETING")


def _delete_pipe(ctx, name: str) -> None:
    """DeletePipe; a ConflictException is retried only while the pipe reads as transitional."""
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            try:
                state = pipes.describe_pipe(Name=name)["CurrentState"]
            except ClientError as describe_exc:
                if describe_exc.response["Error"]["Code"] == "NotFoundException":
                    return
                raise
            if state not in _TRANSITIONAL_PIPE_STATES:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
