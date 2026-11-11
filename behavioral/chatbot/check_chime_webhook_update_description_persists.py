"""chime-webhook-update-description-persists."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "chime-webhook-update-description-persists"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChimeWebhookConfiguration's new WebhookDescription is visible on the next describe."""
    cfg = _create_chime_webhook(ctx, description="before update")
    chatbot = ctx.client("chatbot")
    arn = cfg["ChatConfigurationArn"]

    chatbot.update_chime_webhook_configuration(ChatConfigurationArn=arn, WebhookDescription="after update")

    resp = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=arn)
    matches = [c for c in resp["WebhookConfigurations"] if c["ChatConfigurationArn"] == arn]
    assert len(matches) == 1, f"expected exactly one config for {arn!r}, got {len(matches)}"
    assert matches[0]["WebhookDescription"] == "after update", (
        f"expected WebhookDescription 'after update', got {matches[0]['WebhookDescription']!r}"
    )


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
        Tags=[{"Key": "sim2real", "Value": "chime-webhook-update-description-persists"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-chatbot-topic-"),
        Tags=[{"Key": "sim2real", "Value": "chime-webhook-update-description-persists"}],
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
        Tags=[{"TagKey": "sim2real", "TagValue": "chime-webhook-update-description-persists"}],
    )
    cfg = resp["WebhookConfiguration"]
    arn = cfg["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn))
    return cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
