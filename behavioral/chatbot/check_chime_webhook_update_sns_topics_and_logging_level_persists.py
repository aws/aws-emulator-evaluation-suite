"""chime-webhook-update-sns-topics-and-logging-level-persists."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "chime-webhook-update-sns-topics-and-logging-level-persists"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChimeWebhookConfiguration replacing SnsTopicArns with a different topic and LoggingLevel NONE with
    INFO is reflected by DescribeChimeWebhookConfigurations: SnsTopicArns is [the new topic] and LoggingLevel INFO."""
    chatbot = ctx.client("chatbot")
    topic_arn_a = _create_sns_topic(ctx)
    topic_arn_b = _create_sns_topic(ctx)
    role_arn = _create_iam_role(ctx)
    config_name = ctx.unique_name("sim2real-chime-topics-")
    webhook_url = _chime_webhook_url(ctx)

    created = chatbot.create_chime_webhook_configuration(
        WebhookDescription="sns/logging update test",
        WebhookUrl=webhook_url,
        SnsTopicArns=[topic_arn_a],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
        LoggingLevel="NONE",
        Tags=[{"TagKey": "sim2real", "TagValue": "chime-webhook-update-persists"}],
    )["WebhookConfiguration"]
    arn = created["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: _safe_delete_chime_webhook(ctx, arn))
    assert created["SnsTopicArns"] == [topic_arn_a], f"expected [{topic_arn_a}], got {created['SnsTopicArns']}"

    chatbot.update_chime_webhook_configuration(
        ChatConfigurationArn=arn,
        SnsTopicArns=[topic_arn_b],
        LoggingLevel="INFO",
    )

    described = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=arn)
    matches = [c for c in described["WebhookConfigurations"] if c["ChatConfigurationArn"] == arn]
    assert len(matches) == 1, f"expected exactly 1 config for {arn}, got {len(matches)}"
    assert matches[0]["SnsTopicArns"] == [topic_arn_b], (
        f"expected SnsTopicArns replaced with [{topic_arn_b}], got {matches[0]['SnsTopicArns']}"
    )
    assert matches[0]["LoggingLevel"] == "INFO", f"expected LoggingLevel='INFO', got {matches[0]['LoggingLevel']!r}"


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-chatbot-topic-")
    arn = sns.create_topic(
        Name=name, Tags=[{"Key": "sim2real", "Value": "chime-webhook-update-persists"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_iam_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-chatbot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "chatbot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "chime-webhook-update-persists"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _chime_webhook_url(ctx) -> str:
    token = ctx.unique_name("tok").replace("_", "-")
    return f"https://hooks.chime.aws/incomingwebhooks/{token}?token={token}x5"


def _safe_delete_chime_webhook(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
