"""queue-policy-statement-for-another-queue-grants-nothing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-policy-statement-for-another-queue-grants-nothing"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-scoped"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SendMessage grant in queue A's policy whose Resource names queue B authorizes nothing on A
    or B; pointing the Resource at A lets the role send to A only, so a policy grants access only
    to the queue it is attached to and only where its Resource matches."""
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    url_a = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-scope-a-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_a))
    url_b = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-scope-b-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_b))
    arn_a = sqs.get_queue_attributes(QueueUrl=url_a, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    arn_b = sqs.get_queue_attributes(QueueUrl=url_b, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    _set_policy(sqs, url_a, _policy(role_arn, arn_a, send_resource=arn_b))
    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))

    seen = _until_allowed(lambda: role_sqs.get_queue_attributes(QueueUrl=url_a, AttributeNames=["QueueArn"]))
    assert seen["Attributes"]["QueueArn"] == arn_a, f"role read QueueArn {seen['Attributes']!r}"

    stored = json.loads(sqs.get_queue_attributes(QueueUrl=url_a, AttributeNames=["Policy"])["Attributes"]["Policy"])
    send_stmt = next(s for s in stored["Statement"] if s.get("Sid") == "send")
    assert send_stmt["Resource"] == arn_b, f"queue A's policy should store queue B's ARN as written, got {send_stmt!r}"

    err = _error(lambda: role_sqs.send_message(QueueUrl=url_a, MessageBody="to-a-under-b-statement"))
    assert err["Code"] == "AccessDenied", f"send to A under a statement naming B gave {err!r}"
    assert err["Message"] == _denied(caller, "sendmessage", arn_a), f"got {err['Message']!r}"
    err = _error(lambda: role_sqs.send_message(QueueUrl=url_b, MessageBody="to-b-via-a-policy"))
    assert err["Code"] == "AccessDenied", f"queue A's policy must not authorize sends to B; got {err!r}"
    assert err["Message"] == _denied(caller, "sendmessage", arn_b), f"got {err['Message']!r}"

    _set_policy(sqs, url_a, _policy(role_arn, arn_a, send_resource=arn_a))
    body = f"to-a-under-a-statement-{role_name}"
    _until_allowed(lambda: role_sqs.send_message(QueueUrl=url_a, MessageBody=body), timeout_s=180.0)
    err = _error(lambda: role_sqs.send_message(QueueUrl=url_b, MessageBody="to-b-still"))
    assert err["Code"] == "AccessDenied", f"B must stay closed after A's fix; got {err!r}"

    on_a = _poll(
        lambda: sqs.receive_message(QueueUrl=url_a, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []),
        lambda msgs: len(msgs) > 0,
        timeout_s=30.0,
    )
    assert [m["Body"] for m in on_a] == [body], f"queue A held {[m['Body'] for m in on_a]!r}, expected [{body!r}]"
    on_b = sqs.receive_message(QueueUrl=url_b, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert on_b == [], f"queue B must hold nothing; owner received {[m['Body'] for m in on_b]!r}"


def _policy(role_arn, queue_arn, *, send_resource):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "read", "Effect": "Allow", "Principal": {"AWS": role_arn},
             "Action": "sqs:GetQueueAttributes", "Resource": queue_arn},
            {"Sid": "send", "Effect": "Allow", "Principal": {"AWS": role_arn},
             "Action": "sqs:SendMessage", "Resource": send_resource},
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
