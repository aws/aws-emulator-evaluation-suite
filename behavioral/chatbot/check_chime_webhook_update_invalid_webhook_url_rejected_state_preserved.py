"""chime-webhook-update-invalid-webhook-url-rejected-state-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "chime-webhook-update-invalid-webhook-url-rejected-state-preserved"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChimeWebhookConfiguration with a non-Chime WebhookUrl and LoggingLevel ERROR fails with
    InvalidRequestException "Invalid request body" and leaves LoggingLevel NONE, while the same update
    with a valid Chime WebhookUrl succeeds and sets LoggingLevel ERROR."""
    chatbot = ctx.client("chatbot")
    topic_arn = _create_sns_topic(ctx)
    role_arn = _create_iam_role(ctx)
    config_name = ctx.unique_name("sim2real-chime-updbad-")
    original_url = _chime_webhook_url(ctx, "orig")

    created = chatbot.create_chime_webhook_configuration(
        WebhookDescription="original",
        WebhookUrl=original_url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
        LoggingLevel="NONE",
    )["WebhookConfiguration"]
    arn = created["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: _safe_delete_chime_webhook(ctx, arn))

    code, message = _error(
        lambda: chatbot.update_chime_webhook_configuration(
            ChatConfigurationArn=arn,
            WebhookUrl="https://example.com/not-a-chime-webhook",
            LoggingLevel="ERROR",
        )
    )
    assert code == "InvalidRequestException", f"unexpected code={code!r}"
    assert message == "Invalid request body", f"unexpected message={message!r}"

    # Effect absent: the failed update did not change LoggingLevel either (both fields
    # were in the same rejected request -- no partial application).
    described = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=arn)
    matches = [c for c in described["WebhookConfigurations"] if c["ChatConfigurationArn"] == arn]
    assert len(matches) == 1
    assert matches[0]["LoggingLevel"] == "NONE", "rejected update partially applied LoggingLevel"

    # Positive control: a valid WebhookUrl on the same field, in the same call shape,
    # succeeds -- ruling out "any update touching WebhookUrl is rejected" as the real rule.
    good_url = _chime_webhook_url(ctx, "new")
    chatbot.update_chime_webhook_configuration(
        ChatConfigurationArn=arn, WebhookUrl=good_url, LoggingLevel="ERROR"
    )
    described_after = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=arn)
    matches_after = [
        c for c in described_after["WebhookConfigurations"] if c["ChatConfigurationArn"] == arn
    ]
    assert matches_after[0]["LoggingLevel"] == "ERROR"


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
