"""iam-role-trusts-sqs-service-principal-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trusts-sqs-service-principal-positive"
GROUP = "iam-trust"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """IAM accepts a role trusting only sqs.amazonaws.com and simulates its SQS policy as "allowed";
    an identically permissioned role trusting the caller round-trips an SQS message with it.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-trust-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    sqs_permission_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:SendMessage", "sqs:GetQueueAttributes"],
                "Resource": queue_arn,
            }
        ],
    }

    # --- Role trusted by the sqs.amazonaws.com service principal ---
    trusted_role_name = ctx.unique_name("sim2real-sqs-trusted-role-")
    trusted_role_arn = _create_role(
        ctx,
        trusted_role_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "sqs.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        },
    )
    iam.put_role_policy(
        RoleName=trusted_role_name, PolicyName="sqs-access", PolicyDocument=json.dumps(sqs_permission_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=trusted_role_name, PolicyName="sqs-access"))

    decision = _simulate_until_allowed(iam, trusted_role_arn, queue_arn, timeout_s=30.0)
    assert decision == "allowed", f"expected the SQS-scoped policy to evaluate as allowed, got {decision}"

    # --- Functional proof: an identically permissioned, self-assumable role
    # can really send and a consumer can really receive the message. ---
    caller_arn = sts.get_caller_identity()["Arn"]
    self_role_name = ctx.unique_name("sim2real-sqs-self-role-")
    self_role_arn = _create_role(
        ctx,
        self_role_name,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": caller_arn}, "Action": "sts:AssumeRole"}],
        },
    )
    iam.put_role_policy(
        RoleName=self_role_name, PolicyName="sqs-access", PolicyDocument=json.dumps(sqs_permission_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=self_role_name, PolicyName="sqs-access"))

    creds = _assume_role_with_retry(sts, self_role_arn, "sim2real-sqs-trust-session")
    assumed_sqs = ctx.client(
        "sqs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    assumed_sqs.send_message(QueueUrl=queue_url, MessageBody="sqs-trust-round-trip")

    body = _wait_for_message_body(sqs, queue_url, timeout_s=30)
    assert body == "sqs-trust-round-trip", f"expected the round-tripped body, got {body!r}"


def _create_role(ctx: Any, role_name: str, trust_doc: dict) -> str:
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _simulate_until_allowed(iam: Any, role_arn: str, queue_arn: str, timeout_s: float = 30.0) -> str:
    """Poll the simulator with a bounded, stated-reason retry (IAM policy propagation lag) instead
    of a fixed sleep, so a target whose real propagation is slower still gets a fair read."""
    deadline = time.monotonic() + timeout_s
    decision = None
    while time.monotonic() < deadline:
        sim = iam.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=["sqs:SendMessage"],
            ResourceArns=[queue_arn],
        )
        decision = sim["EvaluationResults"][0]["EvalDecision"]
        if decision == "allowed":
            return decision
        time.sleep(3)
    raise AssertionError(f"policy never evaluated as allowed within {timeout_s}s: last decision {decision}")


def _assume_role_with_retry(sts, role_arn: str, session_name: str, timeout_s: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except Exception as exc:  # noqa: BLE001 - IAM role propagation lag, retry
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_err}")


def _wait_for_message_body(sqs, queue_url: str, timeout_s: float = 30.0) -> str | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
