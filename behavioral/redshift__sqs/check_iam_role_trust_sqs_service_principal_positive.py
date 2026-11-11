"""iam-role-trust-sqs-service-principal-positive."""
from __future__ import annotations

import json
import time

import botocore

from behavioral_harness import tags

CHECK = "iam-role-trust-sqs-service-principal-positive"
GROUP = "permission-boundary"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting sqs.amazonaws.com (and the account root) stores that trust statement, and once
    assumed it sends a message the queue returns as "delivered-via-assumed-role"."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sqs = ctx.client("sqs")
    account_id = sts.get_caller_identity()["Account"]

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-iamtrust-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_name = ctx.unique_name("sim2real-rs-sqs-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TrustSqsService",
                "Effect": "Allow",
                "Principal": {"Service": "sqs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                "Sid": "TrustAccountRootForTest",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    send_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
            }
        ],
    }
    policy_name = "sim2real-send-message"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(send_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    stored = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert any(
        s.get("Principal", {}).get("Service") == "sqs.amazonaws.com" for s in stored["Statement"]
    ), "sqs.amazonaws.com trust statement was not persisted"

    creds = _assume_role_with_retry(sts, role_arn, ctx.unique_name("sim2real-sess-"))
    role_sqs = _client_with_creds(ctx, "sqs", creds)
    _send_message_with_retry(
        role_sqs, queue_url, "delivered-via-assumed-role", timeout_s=30
    )

    msg = _wait_for_message(sqs, queue_url, timeout_s=30)
    assert msg is not None, "assumed role could not deliver the message to SQS"
    assert msg == "delivered-via-assumed-role", f"expected the round-tripped body, got {msg!r}"


def _assume_role_with_retry(sts, role_arn, session_name, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except botocore.exceptions.ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            time.sleep(2)
    raise AssertionError(f"could not assume role within {timeout_s}s: {last_exc}")


def _client_with_creds(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _send_message_with_retry(role_sqs, queue_url, body, timeout_s=30.0):
    """Freshly-minted temporary credentials from a just-created role can take
    a few seconds to become valid everywhere (global STS/IAM propagation);
    retry on the transient InvalidClientTokenId/AccessDenied window instead
    of failing on the first attempt."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            role_sqs.send_message(QueueUrl=queue_url, MessageBody=body)
            return
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "AccessDenied"):
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"could not send message within {timeout_s}s: {last_exc}")


def _wait_for_message(sqs, queue_url, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            return m["Body"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
