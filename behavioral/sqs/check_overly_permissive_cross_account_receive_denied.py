"""overly-permissive-cross-account-receive-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-cross-account-receive-denied"
GROUP = "overly-permissive"
SERVICES = ["sqs"]



@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReceiveMessage by an IAM principal the queue does not grant is denied with the exact
    AccessDenied message and the queue polls to one visible message; AddPermission plus an
    identity-based allow then lets the same principal receive and delete it."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    own_account_id = sts.get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-ovp-recv-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.send_message(QueueUrl=url, MessageBody="cross-account-guarded-body")
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    user_name, access_key_id, secret_access_key = _create_restricted_iam_user(ctx)
    restricted_sqs = _client_with_creds(ctx, "sqs", access_key_id, secret_access_key)
    _wait_for_credentials_active(ctx, access_key_id, secret_access_key)

    # baseline: with no queue policy at all, an IAM principal whose own identity policy
    # grants no SQS permissions is denied (no AddPermission grant => no access)
    err = _client_error(
        lambda: restricted_sqs.receive_message(QueueUrl=url, WaitTimeSeconds=1)
    )
    assert err.get("Code") == "AccessDenied", f"expected AccessDenied for an ungranted principal, got {err!r}"
    user_arn = f"arn:aws:iam::{own_account_id}:user/{user_name}"
    assert err.get("Message") == _denied_message(user_arn, "sqs:receivemessage", queue_arn), f"got {err!r}"


    # effect absent: the message is still on the queue, untouched by the denied attempt
    _poll_queue_counters(ctx, sqs, url, {"ApproximateNumberOfMessages": "1"})

    # positive control: granting the caller's own account ReceiveMessage+DeleteMessage
    # via AddPermission (queue resource policy) together with an IAM identity-based
    # allow (either policy type is sufficient for same-account access per AWS docs)
    # lets the same IAM user receive and delete it. AddPermission normally grants another
    # account; with a single account the grant names our own.
    allow_label = ctx.unique_name("AllowRecvLabel")
    ctx.on_cleanup(lambda: _try(lambda: sqs.remove_permission(QueueUrl=url, Label=allow_label)))
    sqs.add_permission(
        QueueUrl=url,
        Label=allow_label,
        AWSAccountIds=[own_account_id],
        Actions=["ReceiveMessage", "DeleteMessage"],
    )
    _grant_identity_policy(
        ctx, user_name, ["sqs:ReceiveMessage", "sqs:DeleteMessage"], queue_arn
    )

    message = _poll_receive_until_allowed(restricted_sqs, url, timeout_s=120, interval_s=3)
    assert message["Body"] == "cross-account-guarded-body", (
        f"expected the originally-sent body once granted, got {message['Body']!r}"
    )
    restricted_sqs.delete_message(QueueUrl=url, ReceiptHandle=message["ReceiptHandle"])


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_queue_counters(ctx, sqs, queue_url, expected, cap_s=90.0):
    """Poll GetQueueAttributes until every named counter equals its expected string value.

    The ApproximateNumberOf* counters may lag up to a minute after producers stop
    (SQS GetQueueAttributes docs), so a single read is not a verdict."""
    budget_s = _budget_s(ctx, cap_s)
    start = time.monotonic()
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=list(expected))["Attributes"]
        observed = {name: attrs.get(name) for name in expected}
        if observed == expected:
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{cap_s}s counter wait ended (last observed {observed}); not graded"
                )
            raise AssertionError(f"queue counters never reached {expected}; last observed {observed}")
        time.sleep(3)


def _denied_message(user_arn, action, queue_arn):
    """The exact AccessDenied message real SQS returns for a principal with no identity grant."""
    return (
        f"User: {user_arn} is not authorized to perform: {action} on resource: {queue_arn} "
        f"because no identity-based policy allows the {action} action"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


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
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
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


def _poll_receive_until_allowed(restricted_sqs, url, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = restricted_sqs.receive_message(QueueUrl=url, WaitTimeSeconds=2)
            msgs = resp.get("Messages", [])
            if msgs:
                return msgs[0]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(
        f"ReceiveMessage never became allowed after grant; last code={last_code}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
