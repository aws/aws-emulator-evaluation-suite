"""list-associations-maxresults-bounds-rejected."""
from __future__ import annotations

import json
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-associations-maxresults-bounds-rejected"
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
    """ListAssociations with MaxResults 0 and 101 (sent with client-side validation off) fails with
    InvalidRequestException "Invalid request body", while MaxResults 50 succeeds with an empty Associations list."""
    chatbot = ctx.client("chatbot")
    unvalidated = ctx.client("chatbot", config=Config(parameter_validation=False))
    cfg = _create_chime_webhook(ctx)
    config_arn = cfg["ChatConfigurationArn"]

    code_low, message_low = _error(
        lambda: unvalidated.list_associations(ChatConfiguration=config_arn, MaxResults=0)
    )
    assert code_low == "InvalidRequestException", f"unexpected code={code_low!r}"
    assert message_low == "Invalid request body", f"unexpected message={message_low!r}"

    code_high, message_high = _error(
        lambda: unvalidated.list_associations(ChatConfiguration=config_arn, MaxResults=101)
    )
    assert code_high == "InvalidRequestException", f"unexpected code={code_high!r}"
    assert message_high == "Invalid request body", f"unexpected message={message_high!r}"

    # Positive control: an in-range MaxResults succeeds and reflects the true (empty) list —
    # nothing was ever associated to this configuration.
    resp = chatbot.list_associations(ChatConfiguration=config_arn, MaxResults=50)
    assert resp["Associations"] == [], f"expected no associations, got {resp['Associations']!r}"


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
        WebhookDescription="assoc-update test webhook",
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
