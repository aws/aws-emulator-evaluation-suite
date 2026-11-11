"""iam-role-trust-policy-sqs-service-principal-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trust-policy-sqs-service-principal-positive"
GROUP = "iam-trust"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A role trusting sqs.amazonaws.com is returned by GetRole with that principal and sts:AssumeRole,
    the simulator allows its sqs:SendMessage policy, and a role with the same policy sends a message
    an independent receive gets back."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    role_name = ctx.unique_name("sim2real-sqs-trust-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sqs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    queue = _create_queue(ctx, "iamtrust-q")
    policy_name = "AllowSendToQueue"
    send_policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue["arn"]}],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=send_policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    got = iam.get_role(RoleName=role_name)["Role"]
    trust_doc = got["AssumeRolePolicyDocument"]
    assert trust_doc["Statement"][0]["Principal"]["Service"] == "sqs.amazonaws.com", (
        f"expected the stored trust principal to be sqs.amazonaws.com, got "
        f"{trust_doc['Statement'][0]['Principal']!r}"
    )
    assert trust_doc["Statement"][0]["Action"] == "sts:AssumeRole", (
        f"expected the stored trust action to be sts:AssumeRole, got {trust_doc['Statement'][0]['Action']!r}"
    )

    decision = _poll_simulate_allowed(ctx, role["Arn"], "sqs:SendMessage", queue["arn"], timeout_s=30.0)
    assert decision == "allowed", (
        f"expected the simulator to agree the attached policy allows sqs:SendMessage, got {decision!r}"
    )

    # --- Functional proof: SimulatePrincipalPolicy is advisory, not enforcement. A second,
    # identically-permissioned role that also trusts this account's root is actually assumed, and
    # the resulting credentials are used to send a real message that an independent reader
    # receives at the queue -- the terminal read this check was missing.
    account_id = sts.get_caller_identity()["Account"]
    fn_role_name = ctx.unique_name("sim2real-sqs-trust-fn-role-")
    fn_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    fn_role = iam.create_role(
        RoleName=fn_role_name,
        AssumeRolePolicyDocument=json.dumps(fn_trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fn_role_name))
    iam.put_role_policy(RoleName=fn_role_name, PolicyName=policy_name, PolicyDocument=send_policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fn_role_name, PolicyName=policy_name))

    creds = _assume_role_with_retry(sts, fn_role["Arn"], ctx.unique_name("sim2real-sqs-trust-sess-"), timeout_s=30.0)
    assumed_sqs = _client_with_creds(ctx, "sqs", creds)
    body = "delivered-via-assumed-role"
    _send_message_with_retry(assumed_sqs, queue["url"], body, timeout_s=30.0)

    received = _wait_for_message_body(ctx.client("sqs"), queue["url"], timeout_s=30.0)
    assert received == body, (
        f"expected the message sent by the assumed role to be received verbatim at the queue, got {received!r}"
    )


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-{suffix}-"), tags={"sim2real": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"url": url, "arn": _queue_arn(sqs, url)}


def _poll_simulate_allowed(ctx, role_arn: str, action: str, resource_arn: str, timeout_s: float = 30.0):
    """IAM policy attachments are eventually consistent; retry the simulator
    until it reflects the just-attached inline policy or the deadline passes."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    decision = None
    while time.monotonic() < deadline:
        resp = iam.simulate_principal_policy(
            PolicySourceArn=role_arn, ActionNames=[action], ResourceArns=[resource_arn]
        )
        decision = resp["EvaluationResults"][0]["EvalDecision"]
        if decision == "allowed":
            return decision
        time.sleep(2)
    return decision


def _assume_role_with_retry(sts, role_arn: str, session_name: str, timeout_s: float = 30.0) -> dict:
    """Freshly-created IAM roles/trust statements propagate across STS/IAM
    with a short lag; retry on the transient AccessDenied window instead of
    failing on the first attempt."""
    import botocore

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_exc}")


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _send_message_with_retry(sqs_client, queue_url: str, body: str, timeout_s: float = 30.0) -> None:
    """Freshly-minted temporary credentials can take a few seconds to become
    valid everywhere; retry on the transient credential-propagation window
    instead of failing on the first attempt."""
    import botocore

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            sqs_client.send_message(QueueUrl=queue_url, MessageBody=body)
            return
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "AccessDenied"):
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"could not send message within {timeout_s}s: {last_exc}")


def _wait_for_message_body(sqs_client, queue_url: str, timeout_s: float = 30.0) -> str | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs_client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
