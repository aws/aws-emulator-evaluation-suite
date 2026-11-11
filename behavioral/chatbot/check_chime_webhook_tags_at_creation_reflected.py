"""chime-webhook-tags-at-creation-reflected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "chime-webhook-tags-at-creation-reflected"
GROUP = "tagging"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied on CreateChimeWebhookConfiguration are visible via ListTagsForResource,
    and TagResource/UntagResource further mutate that same set."""
    chatbot = ctx.client("chatbot")
    role_arn = _create_chatbot_role(ctx)
    topic_arn = _create_sns_topic(ctx)
    config_name = ctx.unique_name("sim2real-chime-")
    url = (
        f"https://hooks.chime.aws/incomingwebhooks/{ctx.unique_name('wh')}"
        f"?token={ctx.unique_name('tok')}"
    )
    resp = chatbot.create_chime_webhook_configuration(
        WebhookDescription="tagged at creation",
        WebhookUrl=url,
        SnsTopicArns=[topic_arn],
        IamRoleArn=role_arn,
        ConfigurationName=config_name,
        Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
    )
    arn = resp["WebhookConfiguration"]["ChatConfigurationArn"]
    ctx.on_cleanup(lambda: chatbot.delete_chime_webhook_configuration(ChatConfigurationArn=arn))

    tags = {t["TagKey"]: t["TagValue"] for t in chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags == {"env": "sim2real"}, f"expected creation-time tags {{'env': 'sim2real'}}, got {tags}"

    chatbot.tag_resource(ResourceARN=arn, Tags=[{"TagKey": "owner", "TagValue": "team-x"}])
    tags2 = {t["TagKey"]: t["TagValue"] for t in chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    expected2 = {"env": "sim2real", "owner": "team-x"}
    assert tags2 == expected2, f"expected {expected2} after TagResource, got {tags2}"

    chatbot.untag_resource(ResourceARN=arn, TagKeys=["env"])
    tags3 = {t["TagKey"]: t["TagValue"] for t in chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags3 == {"owner": "team-x"}, f"expected only {{'owner': 'team-x'}} after UntagResource, got {tags3}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
