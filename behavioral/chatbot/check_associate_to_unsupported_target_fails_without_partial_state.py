"""associate-to-unsupported-target-fails-without-partial-state."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-to-unsupported-target-fails-without-partial-state"
GROUP = "association"
SERVICES = ["chatbot"]


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateToConfiguration linking an existing custom action to a Chime webhook configuration fails with
    InternalServiceError "Internal Server Error", ListAssociations shows no association before or after, and
    the custom action keeps its definition."""
    chatbot = ctx.client("chatbot")
    cfg = _create_chime_webhook(ctx)
    config_arn = cfg["ChatConfigurationArn"]
    action_arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo assoc"},
        Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=action_arn))

    before = chatbot.list_associations(ChatConfiguration=config_arn)["Associations"]
    assert not any(a["Resource"] == action_arn for a in before), (
        f"expected no pre-existing association for {action_arn!r}, got {before!r}"
    )

    code, message = _error(
        lambda: chatbot.associate_to_configuration(Resource=action_arn, ChatConfiguration=config_arn)
    )
    assert code == "InternalServiceError", f"unexpected code={code!r}"
    assert message == "Internal Server Error", f"unexpected message={message!r}"

    after = chatbot.list_associations(ChatConfiguration=config_arn)["Associations"]
    assert not any(a["Resource"] == action_arn for a in after), (
        "a failed AssociateToConfiguration must not leave a partial association"
    )

    # The custom action itself is unaffected by the failed association attempt.
    got = chatbot.get_custom_action(CustomActionArn=action_arn)["CustomAction"]
    assert got["CustomActionArn"] == action_arn, (
        f"expected unaffected custom action {action_arn!r}, got {got.get('CustomActionArn')!r}"
    )
    assert got["Definition"]["CommandText"] == "echo assoc", (
        f"expected custom action Definition untouched by the failed associate, got {got['Definition']!r}"
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
        Tags=[{"Key": "Name", "Value": name}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-chatbot-topic-"),
        Tags=[{"Key": "env", "Value": "sim2real"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_chime_webhook(ctx) -> dict[str, Any]:
    chatbot = ctx.client("chatbot")
    role_arn = _create_chatbot_role(ctx)
    topic_arn = _create_sns_topic(ctx)
    config_name = ctx.unique_name("sim2real-chime-")
    url = (
        f"https://hooks.chime.aws/incomingwebhooks/{ctx.unique_name('wh')}"
        f"?token={ctx.unique_name('tok')}"
    )
    resp = chatbot.create_chime_webhook_configuration(
        WebhookDescription="assoc test webhook",
        WebhookUrl=url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
        Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
    )
    cfg = resp["WebhookConfiguration"]
    arn = cfg["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn))
    return cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
