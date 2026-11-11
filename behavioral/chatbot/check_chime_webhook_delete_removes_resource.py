"""chime-webhook-delete-removes-resource."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "chime-webhook-delete-removes-resource"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


def _delete_tolerating_slr_propagation(fn, *, timeout_s: float = 30.0, interval_s: float = 3.0):
    """DeleteChimeWebhookConfiguration unsubscribes SNS topics via AWS Chatbot's
    service-linked role. On an account's first-ever use of that role, AWS can reject the
    call for a few seconds while the role finishes propagating (its own documented
    guidance: "wait a few seconds and try again") -- this is genuine eventual consistency,
    not a defect, so it gets a bounded retry rather than being asserted away."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") == "InvalidRequestException"
                and "service-linked role" in err.get("Message", "")
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteChimeWebhookConfiguration the config disappears from Describe and a
    second delete on the same ARN is rejected as not found."""
    cfg = _create_chime_webhook(ctx)
    chatbot = ctx.client("chatbot")
    arn = cfg["ChatConfigurationArn"]

    before = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=arn)["WebhookConfigurations"]
    assert any(c["ChatConfigurationArn"] == arn for c in before), (
        f"expected {arn} in DescribeChimeWebhookConfigurations right after create, got {before!r}"
    )

    _delete_tolerating_slr_propagation(
        lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn)
    )

    after = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=arn)["WebhookConfigurations"]
    assert not any(c["ChatConfigurationArn"] == arn for c in after), (
        f"expected {arn} gone from DescribeChimeWebhookConfigurations after delete, still saw {after!r}"
    )

    code, message = _error(lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on re-delete, got {code!r}"
    assert message == f"Resource {arn} does not exist!", f"unexpected message={message!r}"


def _create_chatbot_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-chatbot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "chatbot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-chatbot-topic-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_chime_webhook(
    ctx, *, name: str | None = None, webhook_url: str | None = None, description: str = "sim2real chime webhook"
) -> dict[str, Any]:
    chatbot = ctx.client("chatbot")
    role_arn = _create_chatbot_role(ctx)
    topic_arn = _create_sns_topic(ctx)
    config_name = name or ctx.unique_name("sim2real-chime-")
    url = webhook_url or (
        f"https://hooks.chime.aws/incomingwebhooks/{ctx.unique_name('wh')}"
        f"?token={ctx.unique_name('tok')}"
    )
    resp = chatbot.create_chime_webhook_configuration(
        WebhookDescription=description,
        WebhookUrl=url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )
    cfg = resp["WebhookConfiguration"]
    arn = cfg["ChatConfigurationArn"]
    def _cleanup() -> None:
        try:
            _delete_tolerating_slr_propagation(
                lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn)
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
