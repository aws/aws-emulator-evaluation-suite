"""chime-webhook-duplicate-configuration-name-conflict-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "chime-webhook-duplicate-configuration-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateChimeWebhookConfiguration with an existing ConfigurationName fails with ConflictException
    "Resource with arn <arn> already exists.", the original keeps its description, and a differently-named
    create succeeds and is readable."""
    chatbot = ctx.client("chatbot")
    topic_arn = _create_sns_topic(ctx)
    role_arn = _create_iam_role(ctx)
    config_name = ctx.unique_name("sim2real-chime-dup-")

    first = chatbot.create_chime_webhook_configuration(
        WebhookDescription="first webhook",
        WebhookUrl=_chime_webhook_url(ctx, "a"),
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
    )["WebhookConfiguration"]
    first_arn = first["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: _safe_delete_chime_webhook(ctx, first_arn))

    code, message = _error(
        lambda: chatbot.create_chime_webhook_configuration(
            WebhookDescription="second webhook, same name",
            WebhookUrl=_chime_webhook_url(ctx, "b"),
            SnsTopicArns=[topic_arn],
            IamRoleArn=role_arn,
            ConfigurationName=config_name,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == f"Resource with arn {first_arn} already exists.", f"unexpected message={message!r}"

    # Effect absent: only the original configuration exists under that name/description.
    described = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=first_arn)
    matches = [c for c in described["WebhookConfigurations"] if c["ChatConfigurationArn"] == first_arn]
    assert len(matches) == 1, f"expected exactly 1 match for {first_arn}, got {matches!r}"
    assert matches[0]["WebhookDescription"] == "first webhook", matches[0]

    # Positive control: a differently-named create in the same account still succeeds,
    # verified with an independent read at the destination (not the create response).
    other_name = ctx.unique_name("sim2real-chime-dup-other-")
    other = chatbot.create_chime_webhook_configuration(
        WebhookDescription="control webhook",
        WebhookUrl=_chime_webhook_url(ctx, "c"),
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=other_name,
    )["WebhookConfiguration"]
    other_arn = other["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: _safe_delete_chime_webhook(ctx, other_arn))
    described_other = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=other_arn)
    other_matches = [
        c for c in described_other["WebhookConfigurations"] if c["ChatConfigurationArn"] == other_arn
    ]
    assert len(other_matches) == 1, f"expected exactly 1 match for {other_arn}, got {other_matches!r}"
    assert other_matches[0]["ConfigurationName"] == other_name, other_matches[0]


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-chatbot-topic-"))["TopicArn"]
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
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _chime_webhook_url(ctx, suffix: str) -> str:
    token = ctx.unique_name("tok").replace("_", "-") + suffix
    return f"https://hooks.chime.aws/incomingwebhooks/{token}?token={token}"


def _safe_delete_chime_webhook(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
