"""chime-webhook-create-state-enabled."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "chime-webhook-create-state-enabled"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created Chime webhook configuration comes up State=ENABLED and is
    returned by DescribeChimeWebhookConfigurations with the exact fields supplied."""
    cfg = _create_chime_webhook(ctx)
    assert cfg["State"] == "ENABLED", f"expected State=ENABLED on create response, got {cfg.get('State')!r}"

    chatbot = ctx.client("chatbot")
    resp = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=cfg["ChatConfigurationArn"])
    matches = [c for c in resp["WebhookConfigurations"] if c["ChatConfigurationArn"] == cfg["ChatConfigurationArn"]]
    assert len(matches) == 1, f"expected exactly one Describe match for {cfg['ChatConfigurationArn']}, got {len(matches)}"
    assert matches[0]["ConfigurationName"] == cfg["ConfigurationName"], (
        f"expected ConfigurationName {cfg['ConfigurationName']!r} on independent read, "
        f"got {matches[0].get('ConfigurationName')!r}"
    )
    assert matches[0]["State"] == "ENABLED", (
        f"expected State=ENABLED on independent read, got {matches[0].get('State')!r}"
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
        Tags=[{"Key": "sim2real", "Value": "chime-webhook-create-state-enabled"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-chatbot-topic-"),
        Tags=[{"Key": "sim2real", "Value": "chime-webhook-create-state-enabled"}],
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
        Tags=[{"TagKey": "sim2real", "TagValue": "chime-webhook-create-state-enabled"}],
    )
    cfg = resp["WebhookConfiguration"]
    arn = cfg["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn))
    return cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
