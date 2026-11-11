"""glue-job-role-missing-sqs-permission-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-job-role-missing-sqs-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A glue-trusting role's session granted sqs:SendMessage on one queue delivers there but
    SendMessage to the other queue raises AccessDenied with the exact message and delivers
    nothing, until the grant is added.
    """
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    allowed_url, allowed_arn = _create_queue(ctx, "allowed")
    blocked_url, blocked_arn = _create_queue(ctx, "blocked")

    role_name, role_arn = _create_dual_trust_role(
        ctx,
        account_id,
        statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": allowed_arn}],
    )
    creds = _assume_role_with_retry(ctx, role_arn, timeout_s=90, interval_s=5)
    sqs_as_role = _sqs_client_from_creds(ctx, creds)

    # Positive control: the role DOES have sqs:SendMessage on this queue.
    sqs_as_role.send_message(QueueUrl=allowed_url, MessageBody="permitted-payload")
    body = _poll_for_message_body(ctx, allowed_url, timeout_s=30, interval_s=2)
    assert body == "permitted-payload", f"positive control failed to deliver: {body!r}"

    # Negative: the role has NO statement covering the blocked queue -> implicit deny.
    code, message = _error(lambda: sqs_as_role.send_message(QueueUrl=blocked_url, MessageBody="should-not-arrive"))
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    session_arn = _session_arn(role_arn, "sim2real-perm-check")
    expected_message = (
        f"User: {session_arn} is not authorized to perform: sqs:sendmessage on resource: {blocked_arn} "
        "because no identity-based policy allows the sqs:sendmessage action"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    missed = _poll_for_message_body(ctx, blocked_url, timeout_s=20, interval_s=2)
    assert missed is None, f"message leaked to a queue the role has no permission for: {missed!r}"

    # Restore: grant the SAME role sqs:SendMessage on the previously-uncovered queue, and demand
    # the IDENTICAL call now succeeds -- this rules out any confound specific to blocked_arn rather
    # than the missing statement.
    _grant_sqs_send(ctx, role_name, blocked_arn)
    _send_with_retry(sqs_as_role, blocked_url, "now-permitted-payload", timeout_s=60, interval_s=5)
    restored = _poll_for_message_body(ctx, blocked_url, timeout_s=30, interval_s=2)
    assert restored == "now-permitted-payload", f"restored call did not deliver: {restored!r}"


def _create_queue(ctx, label: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-glue-{label}-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_dual_trust_role(ctx, account_id: str, statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-perms", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-perms"))
    return role_name, role_arn


def _grant_sqs_send(ctx, role_name: str, queue_arn: str) -> None:
    """Widen the role's own inline policy to also cover queue_arn (the restore step)."""
    iam = ctx.client("iam")
    current = iam.get_role_policy(RoleName=role_name, PolicyName="inline-perms")["PolicyDocument"]
    current["Statement"].append({"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn})
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-perms", PolicyDocument=json.dumps(current))


def _send_with_retry(sqs_as_role, queue_url: str, body: str, *, timeout_s: float, interval_s: float) -> None:
    """IAM policy widening is eventually consistent -- retry the identical call until it is
    honoured, bounded by timeout_s, rather than assuming instant propagation."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sqs_as_role.send_message(QueueUrl=queue_url, MessageBody=body)
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"restored send_message kept failing within {timeout_s}s: {last_err}")


def _assume_role_with_retry(ctx, role_arn: str, timeout_s: float = 90, interval_s: float = 5) -> dict[str, Any]:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-perm-check")
            return resp["Credentials"]
        except Exception as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"assume_role kept failing: {last_err}")


def _sqs_client_from_creds(ctx, creds: dict[str, Any]):
    return ctx.client(
        "sqs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll_for_message_body(ctx, queue_url: str, timeout_s: float = 30, interval_s: float = 2) -> str | None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
        time.sleep(max(0.0, interval_s - 2))
    return None


def _session_arn(role_arn: str, session_name: str) -> str:
    """The assumed-role session ARN STS mints for ``role_arn`` (path-free role names)."""
    _, partition, _, _, account, resource = role_arn.split(":", 5)
    return f"arn:{partition}:sts::{account}:assumed-role/{resource.split('/')[-1]}/{session_name}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
