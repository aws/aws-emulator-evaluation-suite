"""disassociate-nonexistent-association-idempotent."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-nonexistent-association-idempotent"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For a custom action whose AssociateToConfiguration to a Chime webhook configuration fails with
    InternalServiceError "Internal Server Error", DisassociateFromConfiguration succeeds twice in a row and
    ListAssociations shows no association after each call."""
    chatbot = ctx.client("chatbot")
    cfg = _create_chime_webhook(ctx)
    config_arn = cfg["ChatConfigurationArn"]
    action_arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo never-assoc"},
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=action_arn))

    # Ground "never associated" in a demonstrated fact, not an assumption: this exact
    # pair cannot be associated at all, because the Chime webhook configuration kind
    # rejects AssociateToConfiguration outright.
    assoc_code, assoc_message = _error(
        lambda: chatbot.associate_to_configuration(Resource=action_arn, ChatConfiguration=config_arn)
    )
    assert assoc_code == "InternalServiceError", (
        f"expected AssociateToConfiguration against a Chime webhook to fail with "
        f"InternalServiceError, got code={assoc_code!r}"
    )
    assert assoc_message == "Internal Server Error", f"unexpected message={assoc_message!r}"

    # Never associated (and, per above, cannot become associated): disassociate must be
    # a no-op, not an error.
    chatbot.disassociate_from_configuration(Resource=action_arn, ChatConfiguration=config_arn)

    associations = chatbot.list_associations(ChatConfiguration=config_arn)["Associations"]
    assert not any(a["Resource"] == action_arn for a in associations), (
        f"expected no association for {action_arn} after a no-op disassociate, "
        f"got associations={associations!r}"
    )

    # Idempotent: calling it again is still a harmless no-op, not an error.
    chatbot.disassociate_from_configuration(Resource=action_arn, ChatConfiguration=config_arn)
    associations2 = chatbot.list_associations(ChatConfiguration=config_arn)["Associations"]
    assert not any(a["Resource"] == action_arn for a in associations2), (
        f"expected no association for {action_arn} after a second no-op disassociate, "
        f"got associations={associations2!r}"
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
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _create_sns_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-chatbot-topic-"))["TopicArn"]
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
        WebhookDescription="idempotent-disassoc test webhook",
        WebhookUrl=url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
    )
    cfg = resp["WebhookConfiguration"]
    arn = cfg["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn))
    return cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
