"""identity-policy-resourcetag-condition-gates-send-message."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-resourcetag-condition-gates-send-message"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-rtag"
TAG_KEY = "team"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A role whose identity policy allows sqs:SendMessage only when aws:ResourceTag/team
    equals "a" sends to a queue tagged team=a and is refused with AccessDenied on a queue
    tagged team=b, enqueueing nothing there.
    """
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    url_a = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-rtag-a-"), tags={TAG_KEY: "a", "sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url_a), "AWS.SimpleQueueService.NonExistentQueue"))
    arn_a = sqs.get_queue_attributes(QueueUrl=url_a, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    url_b = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-rtag-b-"), tags={TAG_KEY: "b", "sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url_b), "AWS.SimpleQueueService.NonExistentQueue"))
    arn_b = sqs.get_queue_attributes(QueueUrl=url_b, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name, role_arn = _create_role(ctx, account)
    _put_role_policy(
        ctx,
        role_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sqs:SendMessage",
                    "Resource": "*",
                    "Condition": {"StringEquals": {f"aws:ResourceTag/{TAG_KEY}": "a"}},
                }
            ],
        },
    )
    restricted_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))
    caller_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"

    # Positive control: the condition's own value (team=a) is admitted, and the message
    # is actually delivered.
    body_a = f"allowed-{role_name}"
    msg_id = _until_allowed(
        lambda: restricted_sqs.send_message(QueueUrl=url_a, MessageBody=body_a), timeout_s=_budget_s(ctx, 120.0)
    )["MessageId"]
    assert msg_id, "SendMessage to the team=a queue must succeed under the matching ResourceTag condition"
    delivered = _receive_one(sqs, url_a, timeout_s=_budget_s(ctx, 30.0))
    assert delivered == body_a, f"queue A must receive the allowed message; got {delivered!r}"

    # Break exactly one thing: same role, same action, a queue tagged team=b instead.
    err = _error(lambda: restricted_sqs.send_message(QueueUrl=url_b, MessageBody="should-be-denied"))
    assert err.get("Code") == "AccessDenied", f"expected AccessDenied for the team=b queue, got {err!r}"
    assert err.get("Message") == _denied_message(caller_arn, arn_b), f"got {err!r}"

    # Effect absent: the denied send enqueued nothing on queue B.
    on_b = sqs.receive_message(QueueUrl=url_b, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", [])
    assert not on_b, f"a denied SendMessage must not have enqueued anything on queue B; received {on_b!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _denied_message(caller_arn: str, queue_arn: str) -> str:
    """The exact AccessDenied message real SQS returns when no identity-based policy
    statement's condition matches the action on this resource."""
    return (
        f"User: {caller_arn} is not authorized to perform: sqs:sendmessage on resource: {queue_arn} "
        f"because no identity-based policy allows the sqs:sendmessage action"
    )


def _error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _until_allowed(fn, *, timeout_s, interval_s=3.0):
    """Call ``fn`` until it stops raising AccessDenied (identity-policy propagation), bounded."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last = exc.response["Error"]["Code"]
        if time.monotonic() > deadline:
            raise TimeoutError(f"call never became allowed within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _receive_one(sqs, url, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]["Body"]
        time.sleep(interval_s)
    raise TimeoutError(f"no message arrived on {url!r} within {timeout_s}s")


def _create_role(ctx, account):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-rtag-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return name, role["Arn"]


def _put_role_policy(ctx, role_name, doc):
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-behav-rtag-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity")
    )
    return policy_name


def _assume(ctx, role_arn, *, interval_s=3.0):
    """Session credentials for ``role_arn``; AssumeRole retries only while the new trust propagates."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=SESSION)["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            if time.monotonic() > deadline:
                raise TimeoutError(f"role {role_arn} was never assumable") from exc
            time.sleep(interval_s)
    return {
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    }


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
