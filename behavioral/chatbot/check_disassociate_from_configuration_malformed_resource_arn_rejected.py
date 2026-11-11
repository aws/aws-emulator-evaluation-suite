"""disassociate-from-configuration-malformed-resource-arn-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disassociate-from-configuration-malformed-resource-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateFromConfiguration with a Resource that is not an ARN fails with UnauthorizedException
    "Unauthorized", while a well-formed custom-action ARN that was never associated disassociates without error
    and ListAssociations shows no association for it."""
    chatbot = ctx.client("chatbot")
    chat_config_arn = _create_chime_config(ctx)

    code, message = _error(
        lambda: chatbot.disassociate_from_configuration(
            Resource="not-a-valid-arn-at-all", ChatConfiguration=chat_config_arn
        )
    )
    # AWS Chatbot evaluates the resource-scoped authorization check before syntax
    # validation for this ARN, so a malformed Resource fails closed with
    # UnauthorizedException rather than a clean InvalidRequestException.
    assert code == "UnauthorizedException", f"unexpected code={code!r}"
    assert message == "Unauthorized", f"unexpected message={message!r}"

    # Positive control: a well-formed custom-action ARN that was never associated
    # disassociates as a harmless no-op (idempotent), not an error.
    action_arn = _create_custom_action(ctx)
    chatbot.disassociate_from_configuration(Resource=action_arn, ChatConfiguration=chat_config_arn)
    associations = chatbot.list_associations(ChatConfiguration=chat_config_arn)["Associations"]
    assert not any(a["Resource"] == action_arn for a in associations)


def _create_custom_action(ctx) -> str:
    chatbot = ctx.client("chatbot")
    name = ctx.unique_name("sim2realdisassocctl").replace("-", "")[:64]
    arn = chatbot.create_custom_action(
        ActionName=name,
        Definition={"CommandText": "echo ctl"},
        Tags=[{"TagKey": "sim2real", "TagValue": "1"}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: _safe_delete_custom_action(ctx, arn))
    return arn


def _safe_delete_custom_action(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_chime_config(ctx) -> str:
    chatbot = ctx.client("chatbot")
    topic_arn = _create_sns_topic(ctx)
    role_arn = _create_iam_role(ctx)
    config_name = ctx.unique_name("sim2real-chime-")
    webhook_url = _chime_webhook_url(ctx)
    created = chatbot.create_chime_webhook_configuration(
        WebhookDescription="disassoc-malformed test webhook",
        WebhookUrl=webhook_url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
        Tags=[{"TagKey": "sim2real", "TagValue": "1"}],
    )["WebhookConfiguration"]
    arn = created["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: _safe_delete_chime_webhook(ctx, arn))
    return arn


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-chatbot-topic-"),
        Tags=[{"Key": "sim2real", "Value": "1"}],
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
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _chime_webhook_url(ctx) -> str:
    token = ctx.unique_name("tok").replace("_", "-")
    return f"https://hooks.chime.aws/incomingwebhooks/{token}?token={token}x6"


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
