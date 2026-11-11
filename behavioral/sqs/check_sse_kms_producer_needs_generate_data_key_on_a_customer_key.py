"""sse-kms-producer-needs-generate-data-key-on-a-customer-key."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sse-kms-producer-needs-generate-data-key-on-a-customer-key"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-kms-producer"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A producer with no KMS permissions can send to an alias/aws/sqs queue but is refused
    kms:GenerateDataKey on a customer-key queue, enqueuing nothing; granting GenerateDataKey on that
    key lets the same session send and the owner receives the body byte-exact."""
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-producer-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))

    cmk_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-cmk-"),
        Attributes={"KmsMasterKeyId": key["Arn"]},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=cmk_url))
    managed_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-awskey-"),
        Attributes={"KmsMasterKeyId": "alias/aws/sqs"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=managed_url))
    cmk_arn = sqs.get_queue_attributes(QueueUrl=cmk_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    managed_arn = sqs.get_queue_attributes(QueueUrl=managed_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    _set_policy(sqs, cmk_url, _policy(role_arn, cmk_arn))
    _set_policy(sqs, managed_url, _policy(role_arn, managed_arn))
    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))

    # Control: the AWS managed key needs no KMS grant for a principal SQS has authorized.
    managed_body = f"aws-managed-key-{role_name}"
    _until_allowed(lambda: role_sqs.send_message(QueueUrl=managed_url, MessageBody=managed_body))
    got = _receive_bodies(sqs, managed_url, 1)
    assert got == [managed_body], f"the alias/aws/sqs queue delivered {got!r}, expected [{managed_body!r}]"

    def _kms_refusal():
        try:
            role_sqs.send_message(QueueUrl=cmk_url, MessageBody="cmk-without-grant")
        except ClientError as exc:
            return exc.response["Error"]
        return {"Code": "<accepted>", "Message": ""}

    err = _poll(_kms_refusal, lambda e: e["Code"] != "AccessDenied", timeout_s=120.0, interval_s=3.0)
    assert err["Code"] == "KMS.AccessDeniedException", f"send to the customer-key queue gave {err!r}"
    expected = (
        f"User: {caller} is not authorized to perform: kms:GenerateDataKey on resource: {key['Arn']} "
        f"because no identity-based policy allows the kms:GenerateDataKey action "
        f"(Service: AWSKMS; Status Code: 400; Error Code: AccessDeniedException; Request ID: <request-id>; Proxy: null)"
    )
    assert _redact_request_id(err["Message"]) == expected, f"got {err['Message']!r}"
    held = sqs.receive_message(QueueUrl=cmk_url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert held == [], f"a KMS-refused send must enqueue nothing; owner received {held!r}"

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-generate-data-key",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "kms:GenerateDataKey", "Resource": key["Arn"]}],
        }),
    )
    body = "customer-key-é中\U0001f600-" + role_name
    _until_kms_allowed(lambda: role_sqs.send_message(QueueUrl=cmk_url, MessageBody=body))
    got = _receive_bodies(sqs, cmk_url, 1)
    assert got == [body], f"the customer-key queue delivered {got!r}, expected [{body!r}]"


def _policy(role_arn, queue_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "producer", "Effect": "Allow", "Principal": {"AWS": role_arn},
             "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    }


def _redact_request_id(message):
    """Replace the KMS request id inside ``message`` with a placeholder, asserting it is a UUID."""
    head, sep, tail = message.partition("; Request ID: ")
    assert sep, f"KMS error message carries no request id: {message!r}"
    request_id, sep2, rest = tail.partition(";")
    uuid.UUID(request_id)
    return f"{head}{sep}<request-id>{sep2}{rest}"


def _until_kms_allowed(fn, *, timeout_s=120.0, interval_s=3.0):
    """Call ``fn`` until KMS stops refusing (IAM propagation of the new grant), bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KMS.AccessDeniedException" or time.monotonic() > deadline:
                raise
        time.sleep(interval_s)


def _receive_bodies(sqs, url, n, timeout_s=30.0):
    bodies = []
    deadline = time.monotonic() + timeout_s
    while len(bodies) < n and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []):
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return bodies


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
