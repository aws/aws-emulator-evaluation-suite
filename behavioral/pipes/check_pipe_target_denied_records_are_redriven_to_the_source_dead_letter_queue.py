"""pipe-target-denied-records-are-redriven-to-the-source-dead-letter-queue."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipe-target-denied-records-are-redriven-to-the-source-dead-letter-queue"
GROUP = "target-failure"
SERVICES = ["pipes"]


# timing:real-time — visibility: 5 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A record the pipe's role may not SendMessage to the target is moved to the SQS source's DLQ
    by its redrive policy; a permitted twin delivers and dead-letters nothing; both stay RUNNING.
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-error-troubleshooting.html"""
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")

    def _wiring(*, may_send: bool) -> dict[str, Any]:
        dlq = _create_queue(ctx)
        source = _create_queue(ctx, VisibilityTimeout="5", RedrivePolicy=json.dumps(
            {"deadLetterTargetArn": dlq["arn"], "maxReceiveCount": "2"}))
        target = _create_queue(ctx)
        statements = _sqs_read_statements(source["arn"])
        if may_send:
            statements.append({"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target["arn"]})
        role = _create_pipe_role(ctx, statements)
        pipe = _create_pipe(ctx, source=source["arn"], target=target["arn"], role_arn=role["arn"],
                            SourceParameters={"SqsQueueParameters": {"BatchSize": 1}})
        return {"dlq": dlq, "source": source, "target": target, "role": role, "pipe": pipe}

    # A permitted twin is the control: granting the permission later does not make the denied
    # pipe deliver, because it keeps using the session it already assumed.
    twin = _wiring(may_send=True)
    denied = _wiring(may_send=False)

    run_id = _xname(ctx, "redrive")
    sqs.send_message(QueueUrl=twin["source"]["url"], MessageBody=f"{run_id}-TWIN")
    sent_id = sqs.send_message(QueueUrl=denied["source"]["url"], MessageBody=f"{run_id}-DENIED")["MessageId"]

    delivered = _await_body(ctx, twin["target"]["url"], f"{run_id}-TWIN", timeout_s=300.0,
                            description="the permitted twin delivering its record")
    assert json.loads(delivered["Body"])["body"] == f"{run_id}-TWIN", (
        f"the twin's target received {delivered['Body'][:300]!r}"
    )

    letter = _await_body(ctx, denied["dlq"]["url"], f"{run_id}-DENIED", timeout_s=300.0,
                         description=(
                             "the record the denied pipe could not deliver reaching the source's "
                             "dead-letter queue"))
    assert letter["MessageId"] == sent_id, (
        f"the dead-lettered message has id {letter['MessageId']!r}, not the one sent ({sent_id!r})"
    )
    attrs = letter.get("Attributes", {})
    assert attrs.get("DeadLetterQueueSourceArn") == denied["source"]["arn"], (
        f"the dead letter names source {attrs.get('DeadLetterQueueSourceArn')!r}, expected "
        f"{denied['source']['arn']!r}"
    )
    assert int(attrs.get("ApproximateReceiveCount", "0")) > 2, (
        f"a record is redriven only after its receive count exceeds maxReceiveCount=2; the dead "
        f"letter reports ApproximateReceiveCount={attrs.get('ApproximateReceiveCount')!r}"
    )

    leaked = _receive_for(ctx, denied["target"]["url"], 10.0)
    assert leaked == [], (
        f"pipe {denied['pipe']!r} has no sqs:SendMessage on its target, yet the target received "
        f"{[m['Body'][:200] for m in leaked]!r}"
    )
    assert _receive_for(ctx, twin["dlq"]["url"], 5.0) == [], (
        "the permitted twin's record was dead-lettered although it was delivered"
    )
    _poll_until(lambda: _outstanding(ctx, denied["source"]["url"]), lambda n: n == 0,
                timeout_s=60.0, interval_s=5.0,
                description="the denied pipe's source draining once its record was redriven")
    for name in (twin["pipe"], denied["pipe"]):
        state = pipes.describe_pipe(Name=name)["CurrentState"]
        assert state == "RUNNING", f"a target failure moved pipe {name!r} to {state!r}"


def _await_body(ctx, queue_url: str, needle: str, *, timeout_s: float, description: str) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   AttributeNames=["All"])
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if needle in msg["Body"]:
                return msg
    raise AssertionError(f"{description}: {needle!r} not received within {timeout_s}s")


def _receive_for(ctx, queue_url: str, seconds: float) -> list[dict]:
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _outstanding(ctx, queue_url: str) -> int:
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])


_PREFIX = "sim2real-pipesgap-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name so any leftover can be found by tag or prefix."""
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED.items()]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result) is truthy; return that result. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        if interval_s > 0:
            time.sleep(interval_s)
    raise AssertionError(
        f"{description}: not satisfied within {timeout_s}s. Last observed value: {last!r}"
    )


def _create_queue(ctx, *, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create a tagged SQS queue, register its teardown, and return {name,url,arn}."""
    sqs = ctx.client("sqs")
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=dict(_MANAGED)
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _sqs_read_statements(source_arn: str) -> list[dict[str, Any]]:
    return [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        }
    ]


def _create_pipe_role(ctx, statements: list[dict[str, Any]]) -> dict[str, str]:
    """Create the pipe execution role (trusts pipes.amazonaws.com) carrying one inline policy."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    policy_name = "pipe-inline"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    _put_role_policy(ctx, role_name, policy_name, statements)
    return {"name": role_name, "arn": arn, "policy": policy_name}


def _put_role_policy(
    ctx, role_name: str, policy_name: str, statements: list[dict[str, Any]]
) -> None:
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def _delete_role(ctx, role_name: str) -> None:
    """Teardown: an IAM role cannot be deleted while it still holds inline policies."""
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_pipe(
    ctx,
    *,
    source: str,
    target: str,
    role_arn: str,
    wait_for: str = "RUNNING",
    timeout_s: float = 300.0,
    **extra: Any,
) -> str:
    """Create a pipe, wait for CurrentState == wait_for, and return its name.

    Pipes assumes the role at CreatePipe time, so a new role can lose the IAM propagation race;
    only the assume-role/PassRole refusals are retried, never a permanent ValidationException.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 10.0)))
    while True:
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState="RUNNING",
                Tags=dict(_MANAGED),
                **extra,
            )
            break
        except ClientError as exc:
            text = str(exc)
            if "cannot be assumed" not in text and "iam:PassRole" not in text:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"pipe {name!r} could not be created: EventBridge Pipes never managed to assume the "
                    f"freshly created execution role {role_arn!r} within 60 s. Last error: {exc!r}"
                ) from exc
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_pipe(ctx, name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name)["CurrentState"],
        lambda s: s == wait_for,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=(
            f"pipe {name!r} reaching CurrentState=={wait_for!r} after CreatePipe (a pipe that "
            f"parks in CREATING or reaches CREATE_FAILED never polls its source)"
        ),
    )
    return name


def _delete_pipe(ctx, name: str) -> None:
    """Teardown: DeletePipe is refused with ConflictException while the pipe is transitioning."""
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 45.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
