"""associate-concurrent-unsupported-target-fails-atomically."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-concurrent-unsupported-target-fails-atomically"
GROUP = "concurrency"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """8 concurrent AssociateToConfiguration calls linking a custom action to a Chime webhook configuration all
    fail with InternalServiceError "Internal Server Error", and ListAssociations shows no association afterwards."""
    chatbot = ctx.client("chatbot")
    cfg = _create_chime_webhook(ctx)
    config_arn = cfg["ChatConfigurationArn"]
    action_arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo racer"},
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=action_arn))

    def _associate():
        try:
            chatbot.associate_to_configuration(Resource=action_arn, ChatConfiguration=config_arn)
            return None
        except ClientError as exc:
            return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_associate) for _ in range(8)]
        results = [f.result() for f in as_completed(futures)]

    assert all(r == ("InternalServiceError", "Internal Server Error") for r in results), (
        f"expected every concurrent AssociateToConfiguration against an unsupported "
        f"target to fail with InternalServiceError 'Internal Server Error', got results={results!r}"
    )

    associations = chatbot.list_associations(ChatConfiguration=config_arn)["Associations"]
    matches = [a for a in associations if a["Resource"] == action_arn]
    assert len(matches) == 0, f"expected zero associations after concurrent failed associate, got {len(matches)}"


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-chatbot-topic-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        WebhookDescription="concurrency test webhook",
        WebhookUrl=url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    cfg = resp["WebhookConfiguration"]
    arn = cfg["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn))
    return cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

