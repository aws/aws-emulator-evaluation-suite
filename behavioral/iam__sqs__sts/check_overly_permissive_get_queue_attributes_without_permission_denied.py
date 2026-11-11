"""overly-permissive-get-queue-attributes-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-get-queue-attributes-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["iam", "sqs", "sts"]

_SESSION = "sim2real-behav-gqa"
_TOKEN_NOT_YET = ("InvalidClientTokenId", "The security token included in the request is invalid.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetQueueAttributes by a role with no identity-based permissions is denied with the exact
    AccessDenied message naming sqs:GetQueueAttributes; granting that exact action on the
    queue's ARN then lets the identical call return the queue's own attributes."""
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-ovp-gqa-"),
        Attributes={"VisibilityTimeout": "45"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION}"
    role_creds = _assume(ctx, role_arn)
    _wait_for_credentials_active(ctx, role_creds)
    role_sqs = ctx.client("sqs", creds=role_creds)

    _GQA_DENIED = _denied(caller, "sqs:getqueueattributes", queue_arn)

    # baseline: a role with no identity-based policy at all is denied
    expect_error(
        lambda: role_sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"]), *_GQA_DENIED
    )

    # restore: granting that exact principal sqs:GetQueueAttributes on this queue's ARN --
    # the one thing that changes -- is what flips the identical call
    _grant_identity_policy(ctx, role_name, "sqs:GetQueueAttributes", queue_arn)
    attrs = _poll_get_until_allowed(role_sqs, url, _GQA_DENIED, timeout_s=120, interval_s=3)

    # effect proven: the now-allowed call returns the queue's own attributes
    assert attrs.get("VisibilityTimeout") == "45", (
        f"expected the allowed GetQueueAttributes to return VisibilityTimeout '45', got {attrs!r}"
    )
    assert attrs.get("QueueArn") == queue_arn, (
        f"expected the allowed GetQueueAttributes to return QueueArn {queue_arn!r}, got {attrs!r}"
    )


def _denied(caller_arn, action, queue_arn):
    """The exact (code, message) real SQS returns for a principal with no identity grant."""
    return (
        "AccessDenied",
        f"User: {caller_arn} is not authorized to perform: {action} on resource: {queue_arn} "
        f"because no identity-based policy allows the {action} action",
    )


def _pair(exc: ClientError) -> tuple[str | None, str | None]:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = _pair(exc)
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _create_role(ctx, account):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-gqarole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    return name, f"arn:aws:iam::{account}:role/{name}"


def _delete_role(iam, name):
    for policy_name in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
    iam.delete_role(RoleName=name)


def _grant_identity_policy(ctx, role_name, action, resource_arn):
    iam = ctx.client("iam")
    policy_name = "sim2real-allow"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource_arn}],
            }
        ),
    )


def _assume(ctx, role_arn):
    """Session credentials for ``role_arn``; AssumeRole retries only the exact denial a new
    role's trust answers while it propagates."""
    sts = ctx.client("sts")
    me = sts.get_caller_identity()["Arn"]
    not_yet = ("AccessDenied",
               f"User: {me} is not authorized to perform: sts:AssumeRole on resource: {role_arn}")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            break
        except ClientError as exc:
            if _pair(exc) != not_yet or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return {
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    }


def _wait_for_credentials_active(ctx, creds, *, timeout_s=60.0, interval_s=3.0):
    """Block until the assumed session itself authenticates (distinct from its authorization),
    retrying only the exact refusal of a token STS has not yet propagated."""
    sts = ctx.client("sts", creds=creds)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sts.get_caller_identity()
            return
        except ClientError as exc:
            if _pair(exc) != _TOKEN_NOT_YET or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_get_until_allowed(role_sqs, url, not_yet, *, timeout_s=120.0, interval_s=3.0):
    """GetQueueAttributes, retrying only the exact ``not_yet`` denial while the grant propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return role_sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
        except ClientError as exc:
            if _pair(exc) != not_yet or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
