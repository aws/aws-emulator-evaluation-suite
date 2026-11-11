"""queue-policy-send-grant-does-not-authorize-receive-or-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-policy-send-grant-does-not-authorize-receive-or-delete"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-producer"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue policy granting only sqs:SendMessage leaves the role's ReceiveMessage, DeleteMessage and
    DeleteMessageBatch AccessDenied, with no delivery consumed and the message redelivered; widening
    the same statement lets the same session receive and delete it.
    """
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sendonly-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    _set_policy(sqs, url, _policy(role_arn, queue_arn, ["sqs:SendMessage"]))
    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))

    body = f"producer-only-{role_name}"
    _until_allowed(lambda: role_sqs.send_message(QueueUrl=url, MessageBody=body))

    err = _error(lambda: role_sqs.receive_message(QueueUrl=url, WaitTimeSeconds=1))
    assert err["Code"] == "AccessDenied", f"a send-only role's ReceiveMessage gave {err!r}"
    assert err["Message"] == _denied(caller, "receivemessage", queue_arn), f"got {err['Message']!r}"

    # Effect absent: the denied receive consumed no delivery of the message.
    first = _receive_one(sqs, url, visibility=3)
    assert first["Body"] == body, f"owner received {first['Body']!r}, expected {body!r}"
    assert first["Attributes"]["ApproximateReceiveCount"] == "1", (
        f"the role's denied ReceiveMessage must not count as a delivery; the owner's first receive "
        f"has ApproximateReceiveCount={first['Attributes']['ApproximateReceiveCount']!r}"
    )

    err = _error(lambda: role_sqs.delete_message(QueueUrl=url, ReceiptHandle=first["ReceiptHandle"]))
    assert err["Code"] == "AccessDenied", f"a send-only role's DeleteMessage gave {err!r}"
    assert err["Message"] == _denied(caller, "deletemessage", queue_arn), f"got {err['Message']!r}"
    err = _error(
        lambda: role_sqs.delete_message_batch(
            QueueUrl=url, Entries=[{"Id": "only", "ReceiptHandle": first["ReceiptHandle"]}]
        )
    )
    assert err["Code"] == "AccessDenied", (
        f"DeleteMessageBatch by a role without sqs:DeleteMessage must be refused as a whole "
        f"request, not reported per entry; got {err!r}"
    )
    assert err["Message"] == _denied(caller, "deletemessage", queue_arn), f"got {err['Message']!r}"

    # Effect absent: neither denied delete removed the message, so it is redelivered.
    again = _receive_one(sqs, url, visibility=30)
    assert again["Body"] == body, f"redelivered body was {again['Body']!r}, expected {body!r}"
    assert again["Attributes"]["ApproximateReceiveCount"] == "2", (
        f"the message should come back as its second delivery, got "
        f"ApproximateReceiveCount={again['Attributes']['ApproximateReceiveCount']!r}"
    )
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=again["ReceiptHandle"], VisibilityTimeout=0)

    # Restore: the same statement widened to Receive and Delete; the same session now consumes.
    _set_policy(
        sqs, url, _policy(role_arn, queue_arn, ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"])
    )
    got = _until_allowed(lambda: _role_receive(role_sqs, url), timeout_s=180.0)
    assert got["Body"] == body, f"the role received {got['Body']!r}, expected {body!r}"
    _until_allowed(lambda: role_sqs.delete_message(QueueUrl=url, ReceiptHandle=got["ReceiptHandle"]))
    counts = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"],
        lambda a: a["ApproximateNumberOfMessages"] == "0" and a["ApproximateNumberOfMessagesNotVisible"] == "0",
        timeout_s=60.0,
    )
    assert counts["ApproximateNumberOfMessages"] == "0", f"queue not empty after the role's delete: {counts!r}"


def _policy(role_arn, queue_arn, actions):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "role", "Effect": "Allow", "Principal": {"AWS": role_arn}, "Action": actions,
             "Resource": queue_arn}
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
