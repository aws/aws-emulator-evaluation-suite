"""sns-sqs-cross-account-topic-policy-delivers."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-sqs-cross-account-topic-policy-delivers"
GROUP = "notification"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A topic policy granting sns:Subscribe to a role with no identity policy lets that role
    subscribe a queue, which then receives the published message; this is the cross-account topic
    policy mechanism."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_url, queue_arn = _create_queue(ctx)
    topic_arn = _create_topic(ctx)
    _allow_sns_to_send_to_queue(ctx, queue_url, queue_arn, topic_arn)

    role_arn = _create_bare_role(ctx, account_id)

    sns = ctx.client("sns")
    root_arn = f"arn:aws:iam::{account_id}:root"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
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
            },
            {
                "Sid": "AllowGrantedPrincipalSubscribe",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "SNS:Subscribe",
                "Resource": topic_arn,
            },
        ],
    }
    _set_topic_policy_with_retry(sns, topic_arn, policy)

    granted_sns = _client_as_role(ctx, "sns", role_arn)
    sub_arn = _assume_role_and_subscribe(granted_sns, topic_arn, queue_arn)
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    published_text = "delivered-via-granted-cross-principal-subscribe"
    sns.publish(TopicArn=topic_arn, Message=published_text)
    body = _poll_for_message(ctx, queue_url, timeout_s=45.0)
    envelope = json.loads(body)
    assert envelope.get("Message") == published_text, (
        f"expected delivered message {published_text!r}, got {envelope.get('Message')!r}"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-q-"),
        tags={"simparity-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-topic-"),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
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
    """An IAM role with a trust policy but no attached/inline identity-based permissions, so any
    access it gets must come purely from a resource-based policy naming its ARN."""
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
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


def _assume_role_and_subscribe(granted_sns, topic_arn: str, queue_arn: str) -> str:

    last_err: Exception | None = None
    for _ in range(10):
        try:
            return granted_sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] == "AuthorizationError":
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"granted principal could not subscribe after retries: {last_err}")


def _set_topic_policy_with_retry(sns, topic_arn: str, policy: dict) -> None:
    """A newly-created IAM role is not always immediately resolvable as a Principal in a
    resource policy (IAM eventual consistency) -- SNS rejects the policy with an
    InvalidParameter error referencing the principal/action until the role has propagated.
    Retry the set_topic_attributes call until it is accepted."""
    last_err: Exception | None = None
    for _ in range(15):
        try:
            sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy))
            return
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] == "InvalidParameter":
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"could not set topic policy referencing new role after retries: {last_err}")


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
