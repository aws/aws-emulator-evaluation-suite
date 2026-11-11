"""iam-role-trusts-sqs-service-positive."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trusts-sqs-service-positive"
GROUP = "arn-resolution"
SERVICES = ["lambda", "pipes", "sqs"]

_SQS_ACTIONS = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A role trusting sqs.amazonaws.com stores that exact trust statement, policy simulation allows
    its SQS consumption actions on the named queue, and the assumed role really receives and deletes
    a message on it."""
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-trust-q-"), tags={"team": "sim2real"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-sqs-trust-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("sqs.amazonaws.com", account_id)),
        Tags=[{"Key": "team", "Value": "sim2real"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    fetched = iam.get_role(RoleName=role_name)
    trust_doc = fetched["Role"]["AssumeRolePolicyDocument"]
    statement = trust_doc["Statement"][0]
    assert statement["Principal"] == {"Service": "sqs.amazonaws.com"}
    assert statement["Action"] == "sts:AssumeRole"
    assert statement["Effect"] == "Allow"

    policy_name = ctx.unique_name("sim2real-sqs-trust-policy-")
    permissions_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": _SQS_ACTIONS, "Resource": queue_arn}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    results = _poll_until(
        lambda: iam.simulate_principal_policy(
            PolicySourceArn=role_arn, ActionNames=_SQS_ACTIONS, ResourceArns=[queue_arn]
        )["EvaluationResults"],
        lambda evals: len(evals) == len(_SQS_ACTIONS)
        and all(r["EvalDecision"] == "allowed" for r in evals),
        timeout_s=30,
        interval_s=2,
    )
    assert results is not None
    by_action = {r["EvalActionName"]: r for r in results}
    for action in _SQS_ACTIONS:
        result = by_action[action]
        assert result["EvalDecision"] == "allowed", (action, result)
        matched = result.get("MatchedStatements", [])
        assert matched, f"no matched statement for {action}"

    # The advisory simulation above never proves the permissions policy actually works --
    # assume the role for real and drive every declared action against the real queue.
    creds = _assume_role_with_retry(sts, role_arn, ctx.unique_name("sim2real-sess-"))
    role_sqs = ctx.client(
        "sqs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    marker = f"sqs-trust-marker-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=marker)

    received = _receive_marker_with_retry(role_sqs, queue_url, marker, timeout_s=30)
    assert received is not None, "assumed role could not receive the marker via sqs:ReceiveMessage"

    role_attrs = role_sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]
    assert role_attrs["QueueArn"] == queue_arn

    role_sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])
    remaining = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
    ).get("Messages", [])
    assert not any(m["Body"] == marker for m in remaining), (
        "marker survived sqs:DeleteMessage issued by the assumed role"
    )


def _trust_policy(service_principal: str, account_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TrustSqsService",
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
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


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _assume_role_with_retry(sts, role_arn: str, session_name: str, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"could not assume role within {timeout_s}s: {last_exc}")


def _receive_marker_with_retry(role_sqs, queue_url: str, marker: str, timeout_s: float = 30.0):
    """Freshly-minted assumed-role credentials can take a few seconds to become valid
    everywhere (global STS/IAM propagation); retry the transient AccessDenied window
    instead of failing on the first attempt."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = role_sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDenied", "InvalidClientTokenId"):
                raise
            last_exc = exc
            time.sleep(2)
            continue
        for msg in resp.get("Messages", []):
            if msg["Body"] == marker:
                return msg
        time.sleep(2)
    if last_exc:
        raise AssertionError(f"could not receive via assumed role within {timeout_s}s: {last_exc}")
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
