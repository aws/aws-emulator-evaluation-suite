"""overly-permissive-delete-queue-without-permission-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-delete-queue-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQueue by an IAM principal with no identity-based permissions is denied with the
    exact AccessDenied message and leaves the queue intact; granting that principal
    sqs:DeleteQueue on the queue ARN lets the identical call succeed and the queue disappears."""
    sqs = ctx.client("sqs")

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-ovp-del-"))["QueueUrl"]
    ctx.on_cleanup(lambda: _try(lambda: sqs.delete_queue(QueueUrl=url)))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    user_name, access_key_id, secret_access_key = _create_restricted_iam_user(ctx)
    restricted_sqs = _client_with_creds(ctx, "sqs", access_key_id, secret_access_key)
    _wait_for_credentials_active(ctx, access_key_id, secret_access_key)

    # baseline: with no grant at all, an IAM principal whose own identity policy grants
    # no SQS permissions is denied (same-account membership alone is not access)
    err = _expect_denied(lambda: restricted_sqs.delete_queue(QueueUrl=url))
    assert err.get("Code") == "AccessDenied", (
        f"expected AccessDenied denying an unpermissioned DeleteQueue, got {err!r}"
    )
    user_arn = f"arn:aws:iam::{ctx.account}:user/{user_name}"
    assert err.get("Message") == _denied_message(user_arn, "sqs:deletequeue", queue_arn), f"got {err!r}"

    # effect absent: the queue still exists, with the same ARN, after the denied attempt
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]
    assert attrs.get("QueueArn") == queue_arn, (
        f"the denied DeleteQueue must leave the queue exactly as it was "
        f"(ARN {queue_arn!r}), got {attrs!r}"
    )

    # restore: granting that exact principal an identity-based sqs:DeleteQueue allow on
    # this queue's ARN -- the one thing that changes -- is what flips the identical call
    _grant_identity_policy(ctx, user_name, "sqs:DeleteQueue", queue_arn)
    _poll_delete_until_allowed(restricted_sqs, url, timeout_s=120, interval_s=3)

    # terminal read: independent of the delete call, at the destination, until the
    # specific not-found code appears
    _poll_until(lambda: _queue_gone(sqs, url), timeout_s=30, interval_s=2)


def _denied_message(user_arn, action, queue_arn):
    """The exact AccessDenied message real SQS returns for a principal with no identity grant."""
    return (
        f"User: {user_arn} is not authorized to perform: {action} on resource: {queue_arn} "
        f"because no identity-based policy allows the {action} action"
    )


def _queue_gone(sqs, url):
    """True once GetQueueAttributes answers the not-found code; False while the queue still
    reads (a delete's propagation is not yet visible). Any other refusal raises."""
    try:
        sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "AWS.SimpleQueueService.NonExistentQueue":
            return True
        raise AssertionError(f"unexpected refusal while polling for deletion: {code!r}") from exc
    return False


def _expect_denied(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected this DeleteQueue to be denied, but it SUCCEEDED and returned {result!r}"
    )


def _try(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "NoSuchEntity",
            "QueueDoesNotExist",
        ):
            raise


def _client_with_creds(ctx, service, access_key_id, secret_access_key):
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _create_restricted_iam_user(ctx):
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-sqs-restricted-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = key["AccessKeyId"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
    )
    return user_name, access_key_id, key["SecretAccessKey"]


def _grant_identity_policy(ctx, user_name, action, resource_arn):
    import json

    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-sqs-allow-")
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": action, "Resource": resource_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _try(
            lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        )
    )


def _wait_for_credentials_active(ctx, access_key_id, secret_access_key, timeout_s=60.0, interval_s=3.0):
    sts_client = _client_with_creds(ctx, "sts", access_key_id, secret_access_key)
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            sts_client.get_caller_identity()
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"IAM access key never became usable: {last_exc}")


def _poll_delete_until_allowed(restricted_sqs, url, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            restricted_sqs.delete_queue(QueueUrl=url)
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"DeleteQueue never became allowed after grant; last code={last_code}")


def _poll_until(predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
