"""queue-policy-source-arn-condition-denies-a-direct-caller."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-policy-source-arn-condition-denies-a-direct-caller"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-direct"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Allow conditioned on ArnEquals aws:SourceArn denies a direct SendMessage (no source ARN):
    AccessDenied, nothing enqueued, while an unconditioned read grant works. Rewriting it as
    ArnEqualsIfExists lets the same session send, so Condition blocks are actually evaluated."""
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-srcarn-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    source_arn = f"arn:aws:sns:{ctx.region}:{account}:{ctx.unique_name('sim2real-behav-topic-')}"

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    _set_policy(sqs, url, _policy(role_arn, queue_arn, {"ArnEquals": {"aws:SourceArn": source_arn}}))
    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))

    # Barrier: the unconditioned statement is in force, so the policy as a whole is.
    seen = _until_allowed(lambda: role_sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"]))
    assert seen["Attributes"]["QueueArn"] == queue_arn, f"role read QueueArn {seen['Attributes']!r}"

    err = _error(lambda: role_sqs.send_message(QueueUrl=url, MessageBody="no-source-arn"))
    assert err["Code"] == "AccessDenied", f"a direct send under an aws:SourceArn condition gave {err!r}"
    assert err["Message"] == _denied(caller, "sendmessage", queue_arn), f"got {err['Message']!r}"
    stored = json.loads(
        sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    )
    send_stmt = next(s for s in stored["Statement"] if s.get("Sid") == "send")
    assert send_stmt["Condition"] == {"ArnEquals": {"aws:SourceArn": source_arn}}, (
        f"stored condition was {send_stmt.get('Condition')!r}"
    )
    # Effect absent: nothing was enqueued by the refused send.
    held = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert held == [], f"a refused send must enqueue nothing; owner received {held!r}"

    # Restore: the same key under IfExists matches its absence.
    _set_policy(sqs, url, _policy(role_arn, queue_arn, {"ArnEqualsIfExists": {"aws:SourceArn": source_arn}}))
    body = f"if-exists-{role_name}"
    _until_allowed(lambda: role_sqs.send_message(QueueUrl=url, MessageBody=body), timeout_s=180.0)
    got = _poll(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []),
        lambda msgs: len(msgs) > 0,
        timeout_s=30.0,
    )
    assert [m["Body"] for m in got] == [body], f"owner received {[m['Body'] for m in got]!r}, expected [{body!r}]"


def _policy(role_arn, queue_arn, send_condition):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "read", "Effect": "Allow", "Principal": {"AWS": role_arn},
             "Action": "sqs:GetQueueAttributes", "Resource": queue_arn},
            {"Sid": "send", "Effect": "Allow", "Principal": {"AWS": role_arn},
             "Action": "sqs:SendMessage", "Resource": queue_arn, "Condition": send_condition},
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
