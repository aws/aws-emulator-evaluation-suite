"""queue-policy-naming-nonexistent-principal-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-policy-naming-nonexistent-principal-rejected"
GROUP = "validation"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-grantee"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A queue policy naming a nonexistent role is refused with InvalidAttributeValue by
    SetQueueAttributes (existing policy stays in force) and by CreateQueue (no queue created); a
    policy naming an existing role is accepted and reads back with that principal.
    """
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-ghostpol-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # Positive control first: a policy naming a role that exists is accepted and enforced.
    role_name, role_arn = _create_role(ctx, account)
    good = _policy(role_arn, queue_arn)
    _set_policy(sqs, url, good)
    stored = json.loads(sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"])
    assert stored["Statement"][0]["Principal"] == {"AWS": role_arn}, f"stored principal {stored['Statement'][0]!r}"
    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))
    _until_allowed(lambda: role_sqs.send_message(QueueUrl=url, MessageBody="before-refused-update"))

    ghost_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-neverexisted-')}"
    err = _error(
        lambda: sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(_policy(ghost_arn, queue_arn))})
    )
    assert err["Code"] == "InvalidAttributeValue", f"a policy naming a nonexistent role gave {err!r}"
    assert err["Message"] == "Invalid value for the parameter Policy.", f"got {err['Message']!r}"

    # Effect absent: the existing policy is untouched and still enforced for its grantee.
    after = json.loads(sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"])
    assert after == stored, f"a refused update changed the stored policy to {after!r}"
    body = f"after-refused-update-{role_name}"
    role_sqs.send_message(QueueUrl=url, MessageBody=body)

    ghost_queue = ctx.unique_name("sim2real-behav-ghostq-")
    err = _error(lambda: sqs.create_queue(QueueName=ghost_queue, Attributes={"Policy": json.dumps(_policy(ghost_arn, queue_arn))}))
    assert err["Code"] == "InvalidAttributeValue", f"CreateQueue with a nonexistent principal gave {err!r}"
    assert err["Message"] == "Invalid value for the parameter Policy.", f"got {err['Message']!r}"
    err = _error(lambda: sqs.get_queue_url(QueueName=ghost_queue))
    assert err["Code"] == "AWS.SimpleQueueService.NonExistentQueue", f"the refused CreateQueue left a queue: {err!r}"
    assert err["Message"] == "The specified queue does not exist.", f"got {err['Message']!r}"

    bodies = []
    deadline = time.monotonic() + 30.0
    while len(bodies) < 2 and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []):
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert sorted(bodies) == sorted(["before-refused-update", body]), f"owner received {bodies!r}"


def _policy(principal_arn, queue_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "grantee", "Effect": "Allow", "Principal": {"AWS": principal_arn},
             "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    }


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
