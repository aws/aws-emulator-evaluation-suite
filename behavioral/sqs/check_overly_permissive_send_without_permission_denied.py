"""overly-permissive-send-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-send-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage by a same-account principal is allowed by an identity policy alone, while an
    account-wide AddPermission grant alone leaves it AccessDenied; adding the identity policy
    restores access, since for same-account principals AddPermission needs a paired identity allow.
    """
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    own_account_id = sts.get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-ovp-send-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    user_a, key_a_id, key_a_secret = _create_restricted_iam_user(ctx)
    user_b, key_b_id, key_b_secret = _create_restricted_iam_user(ctx)
    sqs_a = _client_with_creds(ctx, "sqs", key_a_id, key_a_secret)
    sqs_b = _client_with_creds(ctx, "sqs", key_b_id, key_b_secret)
    _wait_for_credentials_active(ctx, key_a_id, key_a_secret)
    _wait_for_credentials_active(ctx, key_b_id, key_b_secret)

    # baseline: neither principal has any grant, and the queue has no resource policy
    # at all, so both are denied.
    arn_a = f"arn:aws:iam::{own_account_id}:user/{user_a}"
    arn_b = f"arn:aws:iam::{own_account_id}:user/{user_b}"
    err_a = _client_error(lambda: sqs_a.send_message(QueueUrl=url, MessageBody="a-should-be-denied"))
    assert err_a.get("Code") == "AccessDenied", f"expected AccessDenied for principal A with no grant, got {err_a!r}"
    assert err_a.get("Message") == _denied_message(arn_a, queue_arn), f"got {err_a!r}"
    err_b = _client_error(lambda: sqs_b.send_message(QueueUrl=url, MessageBody="b-should-be-denied"))
    assert err_b.get("Code") == "AccessDenied", f"expected AccessDenied for principal B with no grant, got {err_b!r}"
    assert err_b.get("Message") == _denied_message(arn_b, queue_arn), f"got {err_b!r}"

    # effect absent: neither denied attempt enqueued anything
    attrs = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"a denied send must not have enqueued anything; got "
        f"ApproximateNumberOfMessages={attrs['ApproximateNumberOfMessages']!r}"
    )

    # leg A: an identity-based allow ALONE for principal A -- the queue still has no
    # resource policy of any kind. Timed, so the negative leg below can calibrate its
    # window to this run's OWN measured latency rather than a borrowed guess.
    leg_a_start = time.monotonic()
    _grant_identity_policy(ctx, user_a, "sqs:SendMessage", queue_arn)
    msg_id_a = _poll_send_until_allowed(
        sqs_a, url, "identity-only-body", timeout_s=120, interval_s=3
    )
    leg_a_latency_s = time.monotonic() - leg_a_start
    assert msg_id_a, "an identity policy alone must be sufficient for same-account SendMessage"

    # twin control, at the same instant: principal B still has zero grants and must
    # still be denied -- proves A's identity grant did not leak account-wide.
    err_b_after_a = _client_error(
        lambda: sqs_b.send_message(QueueUrl=url, MessageBody="b-still-denied")
    )
    assert err_b_after_a.get("Code") == "AccessDenied", (
        f"principal A's identity grant must not affect principal B, which still has none; "
        f"got {err_b_after_a!r}"
    )
    assert err_b_after_a.get("Message") == _denied_message(arn_b, queue_arn), f"got {err_b_after_a!r}"

    # leg B, negative: an account-wide AddPermission grant, with NO identity policy for
    # B, must NOT be sufficient by itself. Calibrated window per this run's OWN measured
    # positive latency (leg A): hold absence for >=3x that, with a floor so a near-instant
    # leg A grant (fast IAM propagation) still gets a meaningful observation window.
    negative_window_s = max(3.0 * leg_a_latency_s, 15.0)
    allow_label = ctx.unique_name("AllowLabel")
    ctx.on_cleanup(lambda: _try(lambda: sqs.remove_permission(QueueUrl=url, Label=allow_label)))
    sqs.add_permission(
        QueueUrl=url,
        Label=allow_label,
        AWSAccountIds=[own_account_id],
        Actions=["SendMessage"],
    )
    stayed_denied, resource_only_codes = _assert_stays_denied(
        sqs_b, url, "resource-only-should-stay-denied", timeout_s=negative_window_s, interval_s=5
    )
    assert stayed_denied, (
        f"an AddPermission grant alone (no identity policy) must not grant access; "
        f"observed codes={resource_only_codes}"
    )

    # leg B, restore: granting B the SAME identity policy A has -- the one remaining
    # variable, with the AddPermission grant untouched -- flips B to allowed. This
    # proves the earlier denial was the missing identity grant,
    # not a broken client, broken credentials, or a mistargeted queue ARN for B.
    _grant_identity_policy(ctx, user_b, "sqs:SendMessage", queue_arn)
    msg_id_b = _poll_send_until_allowed(
        sqs_b, url, "identity-plus-resource-body", timeout_s=120, interval_s=3
    )
    assert msg_id_b, "adding the identity policy on top of the existing AddPermission grant must restore access"


def _denied_message(user_arn, queue_arn):
    """The exact AccessDenied message real SQS returns for a SendMessage by a principal with no
    identity grant."""
    return (
        f"User: {user_arn} is not authorized to perform: sqs:sendmessage on resource: {queue_arn} "
        f"because no identity-based policy allows the sqs:sendmessage action"
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
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = key["AccessKeyId"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
    )
    return user_name, access_key_id, key["SecretAccessKey"]


def _grant_identity_policy(ctx, user_name, action, resource_arn):
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
    return policy_name


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


def _assert_stays_denied(restricted_sqs, url, body, *, timeout_s, interval_s):
    """Repeatedly probes SendMessage; returns (True, codes) if every attempt over the
    window was denied, or (False, codes) the moment one unexpectedly succeeds."""
    deadline = time.monotonic() + timeout_s
    codes = []
    while time.monotonic() < deadline:
        try:
            restricted_sqs.send_message(QueueUrl=url, MessageBody=body)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            codes.append(code)
            if code != "AccessDenied":
                return False, codes
        else:
            codes.append("<succeeded>")
            return False, codes
        time.sleep(interval_s)
    return True, codes


def _poll_send_until_allowed(restricted_sqs, url, body, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return restricted_sqs.send_message(QueueUrl=url, MessageBody=body)["MessageId"]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"SendMessage never became allowed after grant; last code={last_code}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
