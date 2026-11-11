"""batch-actions-authorize-under-their-singular-action."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-actions-authorize-under-their-singular-action"
GROUP = "authorization"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-batcher"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SQS authorizes batch APIs under their singular actions: a role allowed only Send, Receive and
    DeleteMessage can batch-send and batch-delete, but ChangeMessageVisibilityBatch is refused
    whole until sqs:ChangeMessageVisibility is granted, then makes every message visible again."""
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-batchauth-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-singular-actions",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"],
                "Resource": queue_arn,
            }],
        }),
    )
    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))

    bodies = {f"m{i}": f"batch-{i}-{role_name}" for i in range(3)}
    sent = _until_allowed(
        lambda: role_sqs.send_message_batch(
            QueueUrl=url, Entries=[{"Id": k, "MessageBody": v} for k, v in bodies.items()]
        )
    )
    assert sent.get("Failed", []) == [], f"SendMessageBatch reported failed entries: {sent.get('Failed')!r}"
    assert sorted(e["Id"] for e in sent["Successful"]) == sorted(bodies), (
        f"SendMessageBatch Successful ids were {sorted(e['Id'] for e in sent['Successful'])!r}"
    )

    held = _receive_all(role_sqs, url, len(bodies), visibility=300)
    assert sorted(m["Body"] for m in held) == sorted(bodies.values()), (
        f"the role received {sorted(m['Body'] for m in held)!r}, expected {sorted(bodies.values())!r}"
    )
    entries = [{"Id": f"h{i}", "ReceiptHandle": m["ReceiptHandle"], "VisibilityTimeout": 0}
               for i, m in enumerate(held)]

    err = _error(lambda: role_sqs.change_message_visibility_batch(QueueUrl=url, Entries=entries))
    assert err["Code"] == "AccessDenied", (
        f"ChangeMessageVisibilityBatch without sqs:ChangeMessageVisibility must be refused as a whole "
        f"request; got {err!r}"
    )
    assert err["Message"] == _denied(caller, "changemessagevisibility", queue_arn), f"got {err['Message']!r}"
    # Effect absent: the messages are still held by the role's 300 s visibility timeout.
    visible = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert visible == [], f"a refused visibility change must leave the messages hidden; owner got {visible!r}"

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-change-visibility",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:ChangeMessageVisibility", "Resource": queue_arn}],
        }),
    )
    changed = _until_allowed(
        lambda: role_sqs.change_message_visibility_batch(QueueUrl=url, Entries=entries), timeout_s=180.0
    )
    assert changed.get("Failed", []) == [], f"ChangeMessageVisibilityBatch failed entries: {changed.get('Failed')!r}"
    assert sorted(e["Id"] for e in changed["Successful"]) == sorted(e["Id"] for e in entries), (
        f"ChangeMessageVisibilityBatch Successful ids were {changed['Successful']!r}"
    )

    again = _receive_all(role_sqs, url, len(bodies), visibility=300)
    assert sorted(m["Body"] for m in again) == sorted(bodies.values()), (
        f"after the visibility reset the role received {sorted(m['Body'] for m in again)!r}"
    )
    deleted = role_sqs.delete_message_batch(
        QueueUrl=url, Entries=[{"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(again)]
    )
    assert deleted.get("Failed", []) == [], f"DeleteMessageBatch failed entries: {deleted.get('Failed')!r}"
    assert len(deleted["Successful"]) == len(bodies), f"DeleteMessageBatch Successful: {deleted['Successful']!r}"
    counts = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"],
        lambda a: a["ApproximateNumberOfMessages"] == "0" and a["ApproximateNumberOfMessagesNotVisible"] == "0",
        timeout_s=60.0,
    )
    assert counts["ApproximateNumberOfMessagesNotVisible"] == "0", f"queue not empty after batch delete: {counts!r}"


def _receive_all(client, url, n, *, visibility, timeout_s=60.0):
    got = {}
    deadline = time.monotonic() + timeout_s
    while len(got) < n and time.monotonic() < deadline:
        for m in client.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, VisibilityTimeout=visibility
        ).get("Messages", []):
            got[m["MessageId"]] = m
    assert len(got) == n, f"received {len(got)} of {n} messages within {timeout_s}s"
    return list(got.values())


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
