"""describe-chime-webhook-configurations-filters-by-arn."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-chime-webhook-configurations-filters-by-arn"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeChimeWebhookConfigurations with a ChatConfigurationArn filter returns
    only that configuration, not other configurations that also exist in the account."""
    chatbot = ctx.client("chatbot")
    topic_arn = _create_sns_topic(ctx)
    role_arn = _create_iam_role(ctx)

    arn_one = _create_chime_config(ctx, topic_arn, role_arn, "one")
    arn_two = _create_chime_config(ctx, topic_arn, role_arn, "two")

    filtered = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=arn_one)
    returned_arns = [c["ChatConfigurationArn"] for c in filtered["WebhookConfigurations"]]
    assert arn_one in returned_arns, f"expected {arn_one} in filtered describe result, got {returned_arns}"
    assert arn_two not in returned_arns, f"expected {arn_two} excluded from filtered describe result, got {returned_arns}"


def _create_chime_config(ctx, topic_arn: str, role_arn: str, suffix: str) -> str:
    chatbot = ctx.client("chatbot")
    config_name = ctx.unique_name(f"sim2real-chime-{suffix}-")
    webhook_url = _chime_webhook_url(ctx, suffix)
    created = chatbot.create_chime_webhook_configuration(
        WebhookDescription=f"filter test webhook {suffix}",
        WebhookUrl=webhook_url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["WebhookConfiguration"]
    arn = created["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: _safe_delete_chime_webhook(ctx, arn))
    return arn


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-chatbot-topic-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _chime_webhook_url(ctx, suffix: str) -> str:
    token = (ctx.unique_name("tok").replace("_", "-") + suffix)
    return f"https://hooks.chime.aws/incomingwebhooks/{token}?token={token}"


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
