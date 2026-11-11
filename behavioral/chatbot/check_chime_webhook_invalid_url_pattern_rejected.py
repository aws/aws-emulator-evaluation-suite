"""chime-webhook-invalid-url-pattern-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "chime-webhook-invalid-url-pattern-rejected"
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
    """CreateChimeWebhookConfiguration rejects a WebhookUrl that does not match the
    required hooks.chime.aws?token=... shape, and no configuration is created for it;
    creating with a valid-shaped URL in the same file still succeeds."""
    chatbot = ctx.client("chatbot")
    role_arn = _create_chatbot_role(ctx)
    topic_arn = _create_sns_topic(ctx)
    bad_name = ctx.unique_name("sim2real-chime-bad-")

    code, message = _error(
        lambda: chatbot.create_chime_webhook_configuration(
            WebhookDescription="bad url",
            WebhookUrl="https://hooks.chime.aws/incomingwebhooks/missing-token-param",
            SnsTopicArns=[topic_arn],
            IamRoleArn=role_arn,
            ConfigurationName=bad_name,
        )
    )
    assert code == "InvalidRequestException", f"unexpected code={code!r}"
    assert message == "Invalid request body", f"unexpected message={message!r}"

    listing = chatbot.describe_chime_webhook_configurations()["WebhookConfigurations"]
    assert not any(
        c["ConfigurationName"] == bad_name for c in listing
    ), f"rejected create still produced a configuration named {bad_name!r}"

    # Positive control: a syntactically valid webhook URL succeeds.
    good_name = ctx.unique_name("sim2real-chime-good-")
    good_url = (
        f"https://hooks.chime.aws/incomingwebhooks/{ctx.unique_name('wh')}"
        f"?token={ctx.unique_name('tok')}"
    )
    resp = chatbot.create_chime_webhook_configuration(
        WebhookDescription="good url",
        WebhookUrl=good_url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=good_name,
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )
    arn = resp["WebhookConfiguration"]["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn))

    # Terminal read: independent of the create call that produced `resp`.
    described = chatbot.describe_chime_webhook_configurations(ChatConfigurationArn=arn)[
        "WebhookConfigurations"
    ]
    assert len(described) == 1, f"expected exactly one configuration for {arn!r}, got {described!r}"
    assert described[0]["State"] == "ENABLED", f"unexpected state={described[0]['State']!r}"


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-chatbot-topic-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
