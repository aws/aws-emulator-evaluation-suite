"""pipes-create-pipe-fifo-target-without-message-group-id-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-create-pipe-fifo-target-without-message-group-id-rejected"

GROUP = "rejection"

SERVICES = ["pipes", "sqs"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreatePipe with a FIFO SQS target and no TargetParameters.SqsQueueParameters is refused with
    ValidationException and creates nothing, while the same call with a MessageGroupId reaches
    RUNNING and delivers into the FIFO queue under that group.
    """
    sqs = ctx.client("sqs")
    source = _create_queue(ctx, VisibilityTimeout="60")
    # ContentBasedDeduplication so the pipe's SendMessage needs no deduplication id of its own;
    # the parameter under test is MessageGroupId and nothing else may differ between the legs.
    target = _create_queue(ctx, fifo=True, ContentBasedDeduplication="true")
    role = _create_pipe_role(ctx, source["arn"], target["arn"])
    group_id = "sim2real-group"

    # --- Positive control, first and end-to-end, so role, queues and IAM propagation are proven.
    control = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        TargetParameters={"SqsQueueParameters": {"MessageGroupId": group_id}},
    )
    marker = _xname(ctx, "fifomark")
    sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": marker}))
    delivered = _wait_for_messages(ctx, target["url"], expected_count=1, timeout_s=180)[0]
    assert marker in delivered["raw"], (
        f"control leg: pipe {control!r} must deliver into the FIFO target; got "
        f"{delivered['raw']!r} instead of a record carrying {marker!r}"
    )
    assert delivered["attributes"].get("MessageGroupId") == group_id, (
        f"control leg: the delivered FIFO message must carry the configured MessageGroupId "
        f"{group_id!r} -- that is the observable the refused parameter controls; got "
        f"{delivered['attributes']!r}"
    )

    # --- Break exactly one thing: drop TargetParameters entirely.
    rejected_name = _xname(ctx, "pipe")
    code, message = _rejected_error(
        ctx,
        Name=rejected_name,
        RoleArn=role["arn"],
        Source=source["arn"],
        Target=target["arn"],
        DesiredState="RUNNING",
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
    )
    assert code == "ValidationException", (
        f"a FIFO target with no TargetParameters.SqsQueueParameters must be refused with "
        f"ValidationException, got {code!r}"
    )
    expected_message = (
        '{"ValidationErrorFields":[{"Name":"TargetParameters.SqsQueueParameters",'
        '"Message":"Missing required target parameter."}]}'
    )
    assert message == expected_message, (
        f"the refusal must carry AWS's exact message {expected_message!r}, got {message!r}"
    )

    # --- The effect is absent.
    assert rejected_name not in _pipe_names(ctx, rejected_name), (
        f"the refused pipe {rejected_name!r} appears in the fully-paginated list_pipes result: "
        f"{sorted(_pipe_names(ctx, rejected_name))!r}"
    )
    describe_code, describe_message = _describe_error(ctx, rejected_name)
    assert describe_code == "NotFoundException", (
        f"describe_pipe on the refused name {rejected_name!r} must raise NotFoundException, got "
        f"{describe_code!r}"
    )
    assert describe_message == f"Pipe {rejected_name} does not exist.", (
        f"describe_pipe on the refused name {rejected_name!r} must carry AWS's exact message "
        f"'Pipe {rejected_name} does not exist.', got {describe_message!r}"
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
            AttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "raw": msg["Body"],
                    "attributes": msg.get("Attributes", {}),
                }
            )
            if delete:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(messages) < expected_count:
        raise AssertionError(
            f"expected {expected_count} message(s) on {queue_url}, got {len(messages)} within "
            f"{timeout_s}s: {messages!r}"
        )
    return messages


def _drain(ctx, queue_url, window_s=20.0):
    """Receive everything that shows up on a queue inside a bounded window; return raw bodies."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        for msg in msgs:
            seen.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


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
    # No API reports when a role becomes assumable; _create_pipe retries on the assume-role errors.
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


def _create_pipe_role(ctx, source_arn: str, target_arn, extra=None) -> dict[str, str]:
    """The standard pipe execution role: read the source queue, send to the target queue(s)."""
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

    Pipes assumes the role at create time, so a fresh role can lose the IAM propagation race; the
    retry is narrowed to the two assume-role messages so a real rejection is never retried.
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


def _rejected_error(ctx, **kwargs) -> tuple[str, str]:
    """Call create_pipe expecting a rejection; return the AWS error (code, message).

    An accepted call raises, after registering teardown for the wrongly-created pipe.
    """
    pipes = ctx.client("pipes")
    name = kwargs.pop("Name")
    try:
        resp = pipes.create_pipe(Name=name, Tags=_xsvc_resource_tags(), **kwargs)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=name))
    raise AssertionError(
        f"create_pipe({name!r}) was ACCEPTED where real AWS rejects it; response {resp!r}"
    )


def _pipe_names(ctx, name_prefix: str) -> set[str]:
    """Every pipe name under a prefix, fully paginated (page one is not the whole answer even
    with a server-side NamePrefix filter)."""
    pipes = ctx.client("pipes")
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NamePrefix": name_prefix}
        if token:
            kwargs["NextToken"] = token
        resp = pipes.list_pipes(**kwargs)
        names.update(p["Name"] for p in resp.get("Pipes", []))
        token = resp.get("NextToken")
        if not token:
            return names


def _describe_error(ctx, name: str) -> tuple[str, str]:
    """describe_pipe's error (code, message) for a name that must not exist (raises if it does)."""
    try:
        resp = ctx.client("pipes").describe_pipe(Name=name)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"describe_pipe({name!r}) succeeded; the pipe exists: {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
