"""pipes-input-template-renders-source-fields-into-target-body."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-input-template-renders-source-fields-into-target-body"

GROUP = "data-transformation"

SERVICES = ["pipes", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A RUNNING pipe renders its InputTemplate into the target message: <$.messageId> and
    <$.body.marker> (a path into the JSON body string) resolve, literals are kept byte-for-byte,
    and the document has exactly the template's keys."""
    sqs = ctx.client("sqs")
    source = _create_queue(ctx, VisibilityTimeout="60")
    target = _create_queue(ctx)
    role = _create_pipe_role(ctx, source["arn"], target["arn"])

    marker = _xname(ctx, "tmpl")
    # A literal double quote and a literal backslash inside the template: the rendering stage must
    # preserve them rather than re-escaping or dropping them.
    literal = 'a"b\\c'
    template = json.dumps(
        {"m": "<$.body.marker>", "mid": "<$.messageId>", "lit": literal}
    )
    pipe = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        TargetParameters={"InputTemplate": template},
    )

    sent = sqs.send_message(
        QueueUrl=source["url"], MessageBody=json.dumps({"marker": marker, "noise": "envelope-only"})
    )
    delivered = _wait_for_messages(ctx, target["url"], expected_count=1, timeout_s=180)[0]
    body = delivered["body"]

    assert isinstance(body, dict), (
        f"the target message must be the rendered template document, which parses to a JSON "
        f"object; got {body!r} (pipe {pipe!r})"
    )
    assert body.get("m") == marker, (
        f"<$.body.marker> must render the source body's marker {marker!r}; got {body.get('m')!r} "
        f"in {body!r} -- an unresolved placeholder here means the template was stored and not "
        f"applied to the record's parsed body"
    )
    assert body.get("mid") == sent["MessageId"], (
        f"<$.messageId> must render the SOURCE message's id {sent['MessageId']!r}; got "
        f"{body.get('mid')!r} in {body!r}"
    )
    assert body.get("lit") == literal, (
        f"the template's literal characters must survive rendering verbatim: expected "
        f"{literal!r}, got {body.get('lit')!r} in {body!r}"
    )
    assert set(body) == {"m", "mid", "lit"}, (
        f"the delivered document must be EXACTLY the rendered template, so no source-envelope key "
        f"may leak into it; expected keys ['lit', 'm', 'mid'], got {sorted(body)!r} in {body!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


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


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append({"body": body, "message_id": msg["MessageId"], "raw": msg["Body"]})
            if delete:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(messages) < expected_count:
        raise AssertionError(
            f"expected {expected_count} message(s) on {queue_url}, got {len(messages)} within "
            f"{timeout_s}s: {messages!r}"
        )
    return messages


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every inline policy removed before deletion."""
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


def _create_pipe_role(ctx, source_arn: str, target_arn: str, extra=None) -> dict[str, str]:
    """The standard pipe execution role: read the source queue, send to the target queue."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
    ]
    statements.extend(extra or [])
    return _create_role(
        ctx, "pipes.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, desired_state="RUNNING",
                 wait_for="RUNNING", **extra) -> str:
    """Create a pipe and wait for CurrentState==wait_for. Returns the pipe name.

    Pipes assumes the role at create time, so a freshly-created role loses the IAM propagation
    race, which the bounded retry rides out.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    last_err = None
    for _ in range(8):
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState=desired_state,
                Tags=_xsvc_resource_tags(),
                **extra,
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or "iam:PassRole" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create pipe {name}: {last_err}")
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == wait_for,
        timeout_s=240.0,
        interval_s=5.0,
        description=f"pipe {name} {wait_for}",
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
