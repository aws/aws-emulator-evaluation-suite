"""queue-policy-principal-tag-condition-gates-send."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-policy-principal-tag-condition-gates-send"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-abac"
TAG_KEY = "sim2real-team"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue policy conditioned on aws:PrincipalTag/sim2real-team = "blue" admits a blue-tagged role
    and refuses a red one with AccessDenied, enqueueing nothing; after retagging red to blue a new
    session of it is admitted.
    """
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-abac-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    blue_name, blue_arn = _create_role(ctx, account, team="blue")
    red_name, red_arn = _create_role(ctx, account, team="red")
    _set_policy(sqs, url, {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "blue-team-sends",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"StringEquals": {f"aws:PrincipalTag/{TAG_KEY}": "blue", "aws:PrincipalAccount": account}},
        }],
    })
    blue_sqs = ctx.client("sqs", creds=_assume(ctx, blue_arn))
    red_sqs = ctx.client("sqs", creds=_assume(ctx, red_arn))

    blue_body = f"from-blue-{blue_name}"
    _until_allowed(lambda: blue_sqs.send_message(QueueUrl=url, MessageBody=blue_body))

    err = _error(lambda: red_sqs.send_message(QueueUrl=url, MessageBody="from-red-while-red"))
    assert err["Code"] == "AccessDenied", f"a red-tagged role's send gave {err!r}"
    red_caller = f"arn:aws:sts::{account}:assumed-role/{red_name}/{SESSION}"
    assert err["Message"] == _denied(red_caller, "sendmessage", queue_arn), f"got {err['Message']!r}"

    first = _drain(sqs, url, 1)
    assert first == [blue_body], f"only the blue role's message may be enqueued; owner received {first!r}"

    iam.tag_role(RoleName=red_name, Tags=[{"Key": TAG_KEY, "Value": "blue"}])
    retagged_sqs = ctx.client("sqs", creds=_assume(ctx, red_arn))
    red_body = f"from-red-after-retag-{red_name}"
    _until_allowed(lambda: retagged_sqs.send_message(QueueUrl=url, MessageBody=red_body), timeout_s=180.0)
    second = _drain(sqs, url, 1)
    assert second == [red_body], f"after the retag the owner received {second!r}, expected [{red_body!r}]"


def _drain(sqs, url, n, timeout_s=30.0):
    bodies = []
    deadline = time.monotonic() + timeout_s
    while len(bodies) < n and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []):
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    extra = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    return bodies + [m["Body"] for m in extra]


def _denied(caller, action, queue_arn):
    return (
        f"User: {caller} is not authorized to perform: sqs:{action} on resource: {queue_arn} "
        f"because no identity-based policy allows the sqs:{action} action"
    )


def _error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _receive_one(sqs, url, *, visibility, timeout_s=60.0):
    def probe():
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2, VisibilityTimeout=visibility,
            AttributeNames=["ApproximateReceiveCount"],
        ).get("Messages", [])
        return msgs[0] if msgs else None

    return _poll(probe, lambda m: m is not None, timeout_s=timeout_s)


def _role_receive(role_sqs, url):
    msgs = role_sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
    if not msgs:
        raise _NotYet()
    return msgs[0]


class _NotYet(Exception):
    pass


def _until_allowed(fn, *, timeout_s=120.0, interval_s=3.0):
    """Call ``fn`` until it stops raising AccessDenied (policy propagation), bounded."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last = exc.response["Error"]["Code"]
        except _NotYet:
            last = "no message yet"
        if time.monotonic() > deadline:
            raise AssertionError(f"call never became allowed within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _poll(probe, predicate, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_role(ctx, account, team=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sqsrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}]
        + ([{"Key": "sim2real-team", "Value": team}] if team else []),
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    return name, f"arn:aws:iam::{account}:role/{name}"


def _delete_role(iam, name):
    for policy_name in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
    iam.delete_role(RoleName=name)


def _assume(ctx, role_arn):
    """Session credentials for ``role_arn``; AssumeRole retries only while the new trust propagates."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=SESSION)["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return {
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    }


def _set_policy(sqs, url, doc):
    """SetQueueAttributes(Policy). SQS refuses a principal IAM has not finished propagating with
    InvalidAttributeValue, so that one refusal is retried, bounded."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(doc)})
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAttributeValue" or time.monotonic() > deadline:
                raise
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
