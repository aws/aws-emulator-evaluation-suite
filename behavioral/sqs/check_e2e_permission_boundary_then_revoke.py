"""e2e-permission-boundary-then-revoke."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-permission-boundary-then-revoke"
GROUP = "e2e_workflows"
SERVICES = ["sqs"]

_DENIAL_MESSAGE = (
    "User: arn:aws:iam::{account}:user/{user} is not authorized to perform: sqs:sendmessage on "
    "resource: {queue_arn} because no identity-based policy allows the sqs:sendmessage action"
)


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A same-account IAM user is denied SendMessage until granted, and denied again after revoke.

    The grant is AddPermission plus an identity policy allowing sqs:SendMessage, the revoke removes
    both; the denials before and after carry the exact AccessDenied message and land no message.
    """
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    account_id = ctx.account

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-permq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    user_name = ctx.unique_name("sim2real-behav-permuser-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id))

    low_priv_creds = {
        "aws_access_key_id": access_key_id,
        "aws_secret_access_key": key["SecretAccessKey"],
    }
    low_priv_sqs = ctx.client("sqs", creds=low_priv_creds)
    low_priv_sts = ctx.client("sts", creds=low_priv_creds)

    # wait for the freshly-created IAM credentials to become usable (well-known
    # IAM eventual-consistency window for new access keys)
    _wait_for_credentials(low_priv_sts, timeout_s=30.0)

    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    expected_denial = _DENIAL_MESSAGE.format(account=account_id, user=user_name, queue_arn=queue_arn)

    # Before any grant: this identity has neither an identity policy nor a
    # resource policy allowing it, so it must be denied.
    body_before = "before-grant"
    error = _client_error(lambda: low_priv_sqs.send_message(QueueUrl=queue_url, MessageBody=body_before))
    assert error.get("Code") == "AccessDenied", f"expected AccessDenied before grant, got {error.get('Code')!r}"
    assert error.get("Message") == expected_denial, (
        f"expected the denial message {expected_denial!r} before grant, got {error.get('Message')!r}"
    )
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
    assert not resp.get("Messages"), "denied send somehow still landed a message"

    sqs.add_permission(
        QueueUrl=queue_url,
        Label="sim2realGrantSend",
        AWSAccountIds=[account_id],
        Actions=["SendMessage"],
    )
    # Some accounts enforce that a same-account IAM principal also needs an
    # explicit identity-based allow alongside the queue's resource policy
    # (belt-and-suspenders access control) -- grant that too so the *combined*
    # grant/revoke lifecycle (queue policy + identity policy) is what's under
    # test, matching how this is done in practice.
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="sim2realAllowSend",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}
                ],
            }
        ),
    )

    body_after = "after-grant"
    delivered, last_code = _poll_until_send_succeeds(low_priv_sqs, queue_url, body_after, timeout_s=150.0)
    if not delivered:
        policy = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]).get("Attributes", {}).get(
            "Policy"
        )
        whoami = low_priv_sts.get_caller_identity()
        assert delivered, (
            f"grantee's SendMessage never succeeded after AddPermission (last error code: {last_code!r}); "
            f"queue policy={policy!r}; grantee identity={whoami!r}"
        )

    granted = None
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline and granted is None:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=3)
        for m in resp.get("Messages", []):
            if m["Body"] == body_after:
                granted = m
            else:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    assert granted is not None, "granted message was never observed on the queue"
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=granted["ReceiptHandle"])

    sqs.remove_permission(QueueUrl=queue_url, Label="sim2realGrantSend")
    iam.delete_user_policy(UserName=user_name, PolicyName="sim2realAllowSend")

    body_revoked = "after-revoke"
    revoked_ok = _poll_until_send_denied(low_priv_sqs, queue_url, body_revoked, timeout_s=300.0)
    if not revoked_ok:
        policy = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]).get("Attributes", {}).get(
            "Policy"
        )
        user_policies = iam.list_user_policies(UserName=user_name).get("PolicyNames")
        assert revoked_ok, (
            "grantee's SendMessage still succeeds after RemovePermission; "
            f"queue policy={policy!r}; remaining inline user policies={user_policies!r}"
        )
    # revocation propagation is not instantaneous -- some sends made *during* the
    # poll above (before access was fully revoked) may have legitimately
    # succeeded and landed on the queue. Drain those known-stale messages, then
    # issue one fresh send with a brand-new body and confirm it is denied and
    # never lands, proving the post-revocation steady state is truly blocked.
    drain_deadline = time.monotonic() + 10.0
    while time.monotonic() < drain_deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        msgs = resp.get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])

    body_final = "after-revoke-steady-state"
    final = _client_error(lambda: low_priv_sqs.send_message(QueueUrl=queue_url, MessageBody=body_final))
    assert final.get("Code") == "AccessDenied", (
        f"expected steady-state AccessDenied post-revocation, got {final.get('Code')!r}"
    )
    assert final.get("Message") == expected_denial, (
        f"expected the denial message {expected_denial!r} post-revocation, got {final.get('Message')!r}"
    )
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
    assert not any(m["Body"] == body_final for m in resp.get("Messages", [])), (
        "a message sent after revocation still landed in the queue"
    )


def _client_error(fn):
    """The botocore Error dict of a rejected call; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_credentials(sts_client, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            sts_client.get_caller_identity()
            return
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            time.sleep(2.0)
    raise AssertionError(f"IAM credentials never became usable (last error: {last_code})")


def _poll_until_send_succeeds(sqs_client, queue_url: str, body: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            sqs_client.send_message(QueueUrl=queue_url, MessageBody=body)
            return True, None
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            time.sleep(3.0)
    return False, last_code



def _poll_until_send_denied(sqs_client, queue_url: str, body: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sqs_client.send_message(QueueUrl=queue_url, MessageBody=body)
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                return True
        time.sleep(5.0)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
