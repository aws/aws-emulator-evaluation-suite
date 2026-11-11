"""iam-role-missing-sqs-trust-assume-role-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-missing-sqs-trust-assume-role-negative"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AssumeRole on a role that trusts only sqs.amazonaws.com raises AccessDenied for the caller,
    while an identical role that trusts the caller is assumable and its credentials round-trip an
    SQS message.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-notrust-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    # --- Negative: role trusts only sqs.amazonaws.com, not us ---
    untrusted_role_name = ctx.unique_name("sim2real-sqs-notrust-role-")
    untrusted_role_arn = _create_role(
        ctx,
        untrusted_role_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "sqs.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        },
    )
    _wait_for_access_denied(sts, untrusted_role_arn, "sim2real-should-fail")

    # --- Positive control: role trusts our own caller ARN ---
    caller_arn = sts.get_caller_identity()["Arn"]
    trusted_role_name = ctx.unique_name("sim2real-sqs-selftrust-role-")
    trusted_role_arn = _create_role(
        ctx,
        trusted_role_name,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": caller_arn}, "Action": "sts:AssumeRole"}],
        },
    )
    permission_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=trusted_role_name, PolicyName="sqs-send", PolicyDocument=json.dumps(permission_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=trusted_role_name, PolicyName="sqs-send"))

    creds = _assume_role_with_retry(sts, trusted_role_arn, "sim2real-sqs-should-succeed")
    assumed_sqs = ctx.client(
        "sqs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    assumed_sqs.send_message(QueueUrl=queue_url, MessageBody="trusted-role-round-trip")
    body = _wait_for_message_body(sqs, queue_url, timeout_s=30)
    assert body == "trusted-role-round-trip"


def _create_role(ctx: Any, role_name: str, trust_doc: dict) -> str:
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _wait_for_access_denied(sts, role_arn: str, session_name: str, timeout_s: float = 30.0) -> None:
    """Bounded retry for the brief window right after CreateRole in which STS may not yet have
    propagated the new role and can surface a transient error other than the trust-policy verdict
    itself. An outright success is never eligible for that grace -- the trust policy names only
    sqs.amazonaws.com, so no amount of propagation delay can make our own caller identity assumable,
    and treating a success as "not yet settled" would let an over-permissive target retry its way
    to a pass."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while True:
        try:
            sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        except Exception as exc:  # noqa: BLE001
            last_code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if last_code == "AccessDenied":
                return
        else:
            raise AssertionError(
                f"expected AccessDenied assuming an untrusted role {role_arn}, but AssumeRole succeeded"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected AccessDenied assuming an untrusted role {role_arn} within {timeout_s}s, "
                f"last observed code={last_code!r}"
            )
        time.sleep(2)


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


def _wait_for_message_body(sqs, queue_url: str, timeout_s: float = 30.0):
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
