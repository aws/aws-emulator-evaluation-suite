"""describe-chime-webhook-configurations-pagination-returns-all-created."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-chime-webhook-configurations-pagination-returns-all-created"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeChimeWebhookConfigurations with MaxResults=1 paginates via NextToken and
    the union of all pages contains every created configuration exactly once."""
    chatbot = ctx.client("chatbot")
    topic_arn = _create_sns_topic(ctx)
    role_arn = _create_iam_role(ctx)

    arns = []
    for i in range(3):
        config_name = ctx.unique_name(f"sim2real-chime-pg{i}-")
        created = chatbot.create_chime_webhook_configuration(
            WebhookDescription=f"pagination test {i}",
            WebhookUrl=_chime_webhook_url(ctx, str(i)),
            SnsTopicArns=[topic_arn],
            IamRoleArn=role_arn,
            ConfigurationName=config_name,
        )["WebhookConfiguration"]
        arn = created["ChatConfigurationArn"]
        arns.append(arn)
        ctx.on_cleanup(lambda a=arn: _safe_delete_chime_webhook(ctx, a))

    seen: list[str] = []
    token = None
    pages = 0
    while True:
        kwargs = {"MaxResults": 1}
        if token:
            kwargs["NextToken"] = token
        resp = chatbot.describe_chime_webhook_configurations(**kwargs)
        page_items = resp.get("WebhookConfigurations", [])
        assert len(page_items) <= 1, "MaxResults=1 page returned more than one item"
        seen.extend(c["ChatConfigurationArn"] for c in page_items)
        pages += 1
        token = resp.get("NextToken")
        if not token or pages > 500:
            break

    for arn in arns:
        matches = [x for x in seen if x == arn]
        assert len(matches) == 1, f"expected exactly one occurrence of {arn} across pages, saw {len(matches)}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
