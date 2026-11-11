"""associate-wrong-resource-type-rejected."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-wrong-resource-type-rejected"
GROUP = "overly-permissive"
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
    """AssociateToConfiguration with the chat configuration's own ARN as Resource (not a custom-action ARN) fails
    with InvalidRequestException "Invalid request body" and creates no association, while a custom action
    created in the same run is readable."""
    chatbot = ctx.client("chatbot")
    cfg = _create_chime_webhook(ctx)
    config_arn = cfg["ChatConfigurationArn"]

    code, message = _error(
        lambda: chatbot.associate_to_configuration(Resource=config_arn, ChatConfiguration=config_arn)
    )
    assert code == "InvalidRequestException", f"unexpected code={code!r}"
    assert message == "Invalid request body", f"unexpected message={message!r}"

    associations = chatbot.list_associations(ChatConfiguration=config_arn)["Associations"]
    assert not any(a["Resource"] == config_arn for a in associations), (
        f"wrong-resource-type ARN {config_arn!r} must not appear as an association after rejection, "
        f"got associations={associations!r}"
    )

    # Positive control: the credentials and Chatbot service are otherwise healthy -- a
    # normal, well-formed Chatbot resource lifecycle still succeeds.
    # Without this, "rejects the wrong-kind ARN" is indistinguishable from "rejects every
    # AssociateToConfiguration call regardless of input".
    action_arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo control"},
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=action_arn))
    got = chatbot.get_custom_action(CustomActionArn=action_arn)["CustomAction"]
    assert got["CustomActionArn"] == action_arn, (
        f"positive control failed: expected {action_arn!r}, got {got.get('CustomActionArn')!r}"
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
        Tags=[{"Key": "sim2real", "Value": "chatbot-wrong-resource-type"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-chatbot-topic-"),
        Tags=[{"Key": "sim2real", "Value": "chatbot-wrong-resource-type"}],
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
        WebhookDescription="wrong-resource-type test webhook",
        WebhookUrl=url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
        Tags=[{"TagKey": "sim2real", "TagValue": "chatbot-wrong-resource-type"}],
    )
    cfg = resp["WebhookConfiguration"]
    arn = cfg["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn))
    return cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
