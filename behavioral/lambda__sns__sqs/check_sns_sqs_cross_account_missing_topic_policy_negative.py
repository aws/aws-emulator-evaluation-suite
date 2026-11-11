"""sns-sqs-cross-account-missing-topic-policy-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-sqs-cross-account-missing-topic-policy-negative"
GROUP = "notification"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A principal the topic policy does not grant sns:Subscribe gets AuthorizationError (exact
    message) and receives nothing, while a permitted subscribe, publish and receive on the same
    topic and queue works."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_url, queue_arn = _create_queue(ctx)
    topic_arn = _create_topic(ctx)
    _allow_sns_to_send_to_queue(ctx, queue_url, queue_arn, topic_arn)

    role_arn = _create_bare_role(ctx, account_id)

    sns = ctx.client("sns")
    root_arn = f"arn:aws:iam::{account_id}:root"
    # Deliberately omit any statement granting role_arn sns:Subscribe -- this replaces SNS's
    # permissive default (same-account) topic policy with a restrictive one scoped only to the
    # owner, which is the missing "cross-account statement" being tested.
    restrictive_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "OwnerFullAccess",
            "Effect": "Allow",
            "Principal": {"AWS": root_arn},
            "Action": [
                "SNS:GetTopicAttributes",
                "SNS:SetTopicAttributes",
                "SNS:AddPermission",
                "SNS:RemovePermission",
                "SNS:DeleteTopic",
                "SNS:Subscribe",
                "SNS:ListSubscriptionsByTopic",
                "SNS:Publish",
                "SNS:Receive",
            ],
            "Resource": topic_arn,
        }],
    }
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(restrictive_policy)
    )

    ungranted_sns = _client_as_role(ctx, "sns", role_arn)
    code, message = None, None
    # Bounded retry: the restrictive policy may take a moment to fully take effect. A Subscribe
    # that succeeds fails the check at once: it creates the subscription the effect-absent step
    # below rules out.
    for _ in range(5):
        code, message = _client_error(
            lambda: ungranted_sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
        )
        if code == "AuthorizationError":
            break
        time.sleep(2)
    assert code == "AuthorizationError", f"expected AuthorizationError, got {code!r}"
    role_name = role_arn.split("/")[-1]
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-xsvc-session "
        f"is not authorized to perform: SNS:Subscribe on resource: {topic_arn} "
        "because no identity-based policy allows the SNS:Subscribe action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: publish and confirm nothing was ever delivered (no subscription exists).
    sns.publish(TopicArn=topic_arn, Message="must-not-be-delivered-to-unsubscribed-queue")
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    assert not resp.get("Messages"), f"unexpected delivery with no subscription: {resp.get('Messages')}"

    # Positive control: the SAME topic/queue pair, subscribed with a properly-permitted
    # (owner) principal, still delivers normally.
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    control_text = "delivered-with-owner-permission-control"
    sns.publish(TopicArn=topic_arn, Message=control_text)
    body = _poll_for_message(ctx, queue_url, timeout_s=45.0)
    envelope = json.loads(body)
    assert envelope.get("Message") == control_text, (
        f"expected {control_text!r}, got {envelope.get('Message')!r}"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": "sim2real-xsvc"}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _client_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-q-"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-topic-"), Tags=_xsvc_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _allow_sns_to_send_to_queue(ctx, queue_url: str, queue_arn: str, topic_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "SQS:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _create_bare_role(ctx, account_id: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-crossprin-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _client_as_role(ctx, service: str, role_arn: str):
    sts = ctx.client("sts")
    last_err: Exception | None = None
    for _ in range(10):
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-xsvc-session")["Credentials"]
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] in ("AccessDenied", "InvalidClientTokenId"):
                time.sleep(2)
                continue
            raise
    else:
        raise AssertionError(f"could not assume role after retries: {last_err}")
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll_for_message(ctx, queue_url: str, timeout_s: float) -> str:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    raise AssertionError(f"no message delivered within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
