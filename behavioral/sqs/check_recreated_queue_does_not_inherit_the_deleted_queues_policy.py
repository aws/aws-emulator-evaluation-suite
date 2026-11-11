"""recreated-queue-does-not-inherit-the-deleted-queues-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recreated-queue-does-not-inherit-the-deleted-queues-policy"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-former-grantee"


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue recreated under a deleted queue's name keeps its URL and ARN but has no Policy and no
    old messages: the old grantee's send is AccessDenied there (NonExistentQueue on the deleted
    queue), and re-attaching the policy lets that session send again."""
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-recreate-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_if_present(sqs, name))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    _set_policy(sqs, url, _policy(role_arn, queue_arn))
    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))
    _until_allowed(lambda: role_sqs.send_message(QueueUrl=url, MessageBody="sent-to-the-old-queue"))

    sqs.delete_queue(QueueUrl=url)
    err = _poll(
        lambda: _send_outcome(role_sqs, url, "sent-after-delete"),
        lambda e: e["Code"] == "AWS.SimpleQueueService.NonExistentQueue",
        timeout_s=60.0,
    )
    assert err["Message"] == "The specified queue does not exist.", f"got {err['Message']!r}"

    new_url = _recreate(sqs, name)
    assert new_url == url, f"recreated queue URL {new_url!r} differs from the original {url!r}"
    attrs = sqs.get_queue_attributes(QueueUrl=new_url, AttributeNames=["All"])["Attributes"]
    assert attrs["QueueArn"] == queue_arn, f"recreated QueueArn {attrs['QueueArn']!r}, expected {queue_arn!r}"
    assert "Policy" not in attrs, f"the recreated queue inherited a Policy: {attrs.get('Policy')!r}"
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"the recreated queue holds old messages: ApproximateNumberOfMessages={attrs['ApproximateNumberOfMessages']!r}"
    )

    err = _error(lambda: role_sqs.send_message(QueueUrl=new_url, MessageBody="sent-to-the-new-queue-unpermitted"))
    assert err["Code"] == "AccessDenied", f"the former grantee's send to the recreated queue gave {err!r}"
    assert err["Message"] == _denied(caller, "sendmessage", queue_arn), f"got {err['Message']!r}"

    _set_policy(sqs, new_url, _policy(role_arn, queue_arn))
    body = f"sent-to-the-new-queue-{role_name}"
    _until_allowed(lambda: role_sqs.send_message(QueueUrl=new_url, MessageBody=body), timeout_s=180.0)
    got = _poll(
        lambda: sqs.receive_message(QueueUrl=new_url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []),
        lambda msgs: len(msgs) > 0,
        timeout_s=30.0,
    )
    assert [m["Body"] for m in got] == [body], f"the recreated queue held {[m['Body'] for m in got]!r}, expected [{body!r}]"


def _send_outcome(client, url, body):
    """The Error dict of a send, or a marker while a just-deleted queue still accepts sends."""
    try:
        client.send_message(QueueUrl=url, MessageBody=body)
    except ClientError as exc:
        return exc.response["Error"]
    return {"Code": "<accepted>", "Message": ""}


def _recreate(sqs, name, timeout_s=180.0):
    """CreateQueue under ``name`` once SQS frees it; only QueueDeletedRecently is retried."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "AWS.SimpleQueueService.QueueDeletedRecently" or time.monotonic() > deadline:
                raise
        time.sleep(5)


def _delete_if_present(sqs, name):
    try:
        url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue":
            return
        raise
    sqs.delete_queue(QueueUrl=url)


def _policy(role_arn, queue_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "grantee", "Effect": "Allow", "Principal": {"AWS": role_arn},
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
