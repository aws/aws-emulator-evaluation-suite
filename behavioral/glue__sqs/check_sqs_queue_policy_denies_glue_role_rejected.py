"""sqs-queue-policy-denies-glue-role-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-queue-policy-denies-glue-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue policy that explicitly denies a role makes its SendMessage raise AccessDenied (exact
    explicit-deny message) and deliver nothing, although its identity policy allows the send;
    removing the Deny restores delivery.
    """
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    allowed_url, allowed_arn = _create_queue(ctx, "allowed")
    denied_url, denied_arn = _create_queue(ctx, "denied")

    role_arn = _create_dual_trust_role(
        ctx,
        account_id,
        # Broad identity-based allow -- both queues are permitted at the IAM-identity layer.
        statements=[
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": [allowed_arn, denied_arn]}
        ],
    )

    # Explicit resource-policy Deny for this specific role on the "denied" queue only.
    sqs = ctx.client("sqs")
    deny_policy = {
        "Version": "2012-10-17",
        "Id": "sim2real-deny-glue-role",
        "Statement": [
            {
                "Sid": "DenyGlueRole",
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": "sqs:SendMessage",
                "Resource": denied_arn,
            }
        ],
    }
    # IAM role principals referenced in a resource policy are validated against IAM at save
    # time; a role created moments ago may not have propagated yet, causing a transient
    # InvalidAttributeValue ("invalid principal") error -- retry until IAM catches up.
    _set_queue_policy_with_retry(sqs, denied_url, deny_policy, timeout_s=60, interval_s=3)

    creds = _assume_role_with_retry(ctx, role_arn, timeout_s=90, interval_s=5)
    sqs_as_role = _sqs_client_from_creds(ctx, creds)

    # Positive control: no resource policy on this queue -> identity allow wins.
    sqs_as_role.send_message(QueueUrl=allowed_url, MessageBody="permitted-payload")
    body = _poll_for_message_body(ctx, allowed_url, timeout_s=30, interval_s=2)
    assert body == "permitted-payload", f"positive control failed to deliver: {body!r}"

    # Negative: explicit resource-policy Deny overrides the identity-based Allow.
    code, message = _error(lambda: sqs_as_role.send_message(QueueUrl=denied_url, MessageBody="should-not-arrive"))
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    session_arn = _session_arn(role_arn, "sim2real-perm-check")
    expected_message = (
        f"User: {session_arn} is not authorized to perform: sqs:sendmessage on resource: {denied_arn} "
        "with an explicit deny in a resource-based policy"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    missed = _poll_for_message_body(ctx, denied_url, timeout_s=20, interval_s=2)
    assert missed is None, f"message leaked to a queue that explicitly denies this role: {missed!r}"

    # Restore: remove the explicit Deny and the identical call succeeds again. Without this
    # leg, "the resource policy blocks the role" is indistinguishable from "SendMessage to this
    # queue is broken for this role for any reason" -- the restore proves it was the Deny, and
    # only the Deny, that stood between the role and the queue.
    _clear_queue_policy_and_confirm_send(sqs, sqs_as_role, denied_url, timeout_s=120, interval_s=5)
    restored = _poll_for_message_body(ctx, denied_url, timeout_s=30, interval_s=2)
    assert restored == "restored-payload", (
        f"removing the Deny did not restore delivery to the queue: {restored!r}"
    )


def _set_queue_policy_with_retry(
    sqs, queue_url: str, policy: dict[str, Any], timeout_s: float = 60, interval_s: float = 3
) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAttributeValue":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"queue policy kept failing to apply (principal not yet propagated?): {last_err}")


_RESOURCE_TAGS = {"sim2real:managed": "true", "sim2real": "sqs-queue-policy-denies-glue-role-rejected"}


def _create_queue(ctx, label: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-glue-{label}-"), tags=_RESOURCE_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_dual_trust_role(ctx, account_id: str, statements: list[dict[str, Any]]) -> str:
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
        Tags=[{"Key": k, "Value": v} for k, v in _RESOURCE_TAGS.items()],
    )
    role_arn = resp["Role"]["Arn"]
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-perms", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-perms"))
    return role_arn


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


def _clear_queue_policy_and_confirm_send(
    sqs, sqs_as_role, queue_url: str, timeout_s: float = 120, interval_s: float = 5
) -> None:
    """Remove the queue's resource policy and retry the identical send until it succeeds --
    removing a Deny is measured near-instant on real SQS, but this stays a bounded retry rather
    than a fixed sleep since propagation is not guaranteed."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": ""})
        try:
            sqs_as_role.send_message(QueueUrl=queue_url, MessageBody="restored-payload")
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"removing the Deny did not restore SendMessage within {timeout_s}s: last error {last_err}"
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
    """Return fn()'s ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
