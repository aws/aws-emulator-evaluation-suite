"""sse-kms-consumer-without-decrypt-drives-message-to-dlq."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sse-kms-consumer-without-decrypt-drives-message-to-dlq"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-kms-consumer"
MAX_RECEIVE_COUNT = 2


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A consumer without kms:Decrypt on the queue's customer key gets KMS.AccessDeniedException on
    receive, each refusal counts as a delivery so the message dead-letters byte-exact after
    maxReceiveCount, and once Decrypt is granted the same session receives a fresh message."""
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-consumer-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-kmsdlq-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-kmssrc-"),
        Attributes={
            "KmsMasterKeyId": key["Arn"],
            "VisibilityTimeout": "2",
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": MAX_RECEIVE_COUNT}),
        },
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    _set_policy(sqs, url, {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "consumer", "Effect": "Allow", "Principal": {"AWS": role_arn},
                       "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"], "Resource": queue_arn}],
    })
    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))

    body = "poisoned-by-missing-decrypt-é中\U0001f600-" + role_name
    sqs.send_message(QueueUrl=url, MessageBody=body)

    refusals = []
    dead = None
    deadline = time.monotonic() + 120.0
    while dead is None and time.monotonic() < deadline:
        try:
            got = role_sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
        except ClientError as exc:
            refusals.append(exc.response["Error"])
        else:
            assert got == [], f"a role without kms:Decrypt must never receive the body; it got {got!r}"
        moved = sqs.receive_message(
            QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=1, AttributeNames=["ApproximateReceiveCount"]
        ).get("Messages", [])
        if moved:
            dead = moved[0]
        else:
            time.sleep(1)
    assert dead is not None, f"the message never reached the DLQ; the role's receives returned {refusals!r}"

    codes = sorted({e["Code"] for e in refusals if e["Code"] != "AccessDenied"})
    assert codes == ["KMS.AccessDeniedException"], f"the role's refused receives returned codes {codes!r}"
    kms_refusal = next(e for e in refusals if e["Code"] == "KMS.AccessDeniedException")
    expected = (
        f"User: {caller} is not authorized to perform: kms:Decrypt on resource: {key['Arn']} "
        f"because no identity-based policy allows the kms:Decrypt action "
        f"(Service: AWSKMS; Status Code: 400; Error Code: AccessDeniedException; Request ID: <request-id>; Proxy: null)"
    )
    assert _redact_request_id(kms_refusal["Message"]) == expected, f"got {kms_refusal['Message']!r}"

    assert dead["Body"] == body, f"the DLQ held {dead['Body']!r}, expected {body!r}"
    assert dead["Attributes"]["ApproximateReceiveCount"] == str(MAX_RECEIVE_COUNT + 1), (
        f"each refused decrypt should have counted as a delivery; the DLQ copy shows "
        f"ApproximateReceiveCount={dead['Attributes']['ApproximateReceiveCount']!r}, expected "
        f"{MAX_RECEIVE_COUNT + 1} ({MAX_RECEIVE_COUNT} refused receives plus this one)"
    )
    sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=dead["ReceiptHandle"])
    left = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert left == [], f"the source queue should be empty after the DLQ move; owner got {left!r}"

    # Restore: grant kms:Decrypt; the same session now consumes a fresh message.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-decrypt",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key["Arn"]}],
        }),
    )
    # Without the redrive, refusals while the grant propagates cannot dead-letter the fresh message.
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"RedrivePolicy": ""})
    fresh = "after-decrypt-grant-" + role_name
    sqs.send_message(QueueUrl=url, MessageBody=fresh)
    received = _until_decrypt(role_sqs, url, timeout_s=180.0)
    assert received["Body"] == fresh, f"the role received {received['Body']!r}, expected {fresh!r}"
    role_sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])


def _until_decrypt(role_sqs, url, *, timeout_s):
    """Receive until the new kms:Decrypt grant propagates and a message arrives, bounded."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            msgs = role_sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
            if last != "KMS.AccessDeniedException":
                raise
            time.sleep(3)
            continue
        if msgs:
            return msgs[0]
    raise AssertionError(f"the role never received the fresh message within {timeout_s}s (last={last!r})")


def _redact_request_id(message):
    """Replace the KMS request id inside ``message`` with a placeholder, asserting it is a UUID."""
    head, sep, tail = message.partition("; Request ID: ")
    assert sep, f"KMS error message carries no request id: {message!r}"
    request_id, sep2, rest = tail.partition(";")
    uuid.UUID(request_id)
    return f"{head}{sep}<request-id>{sep2}{rest}"


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
