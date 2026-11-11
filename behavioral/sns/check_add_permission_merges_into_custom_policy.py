"""add-permission-merges-into-custom-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "add-permission-merges-into-custom-policy"
GROUP = 'topic-policy'
SERVICES = ['sns']


def _statements(sns, arn):
    return {s.get("Sid"): s for s in json.loads(
        sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"]).get("Statement", [])}


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddPermission appends a statement granting the named actions to the account on this topic
    to a custom SetTopicAttributes policy, leaving it intact; RemovePermission removes only that
    statement."""
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-polmerge-"),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    account = arn.split(":")[4]

    custom = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "CustomOwnerGetAttributes",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "SNS:GetTopicAttributes",
            "Resource": arn,
        }],
    }
    sns.set_topic_attributes(TopicArn=arn, AttributeName="Policy", AttributeValue=json.dumps(custom))
    assert set(_statements(sns, arn)) == {"CustomOwnerGetAttributes"}, "the custom policy must replace the default"

    label = ctx.unique_name("sim2real-behav-lbl-")
    sns.add_permission(TopicArn=arn, Label=label, AWSAccountId=[account],
                       ActionName=["Publish", "Subscribe"])
    stmts = _statements(sns, arn)
    assert set(stmts) == {"CustomOwnerGetAttributes", label}, (
        f"AddPermission must append to the custom policy, got Sids {sorted(stmts)!r}"
    )
    added = stmts[label]
    actions = added.get("Action")
    actions = sorted(actions if isinstance(actions, list) else [actions])
    principal = added.get("Principal", {}).get("AWS")
    principal = principal if isinstance(principal, list) else [principal]
    assert added.get("Effect") == "Allow", f"the added statement's Effect is {added.get('Effect')!r}"
    assert actions == ["SNS:Publish", "SNS:Subscribe"], f"the added statement's actions are {actions!r}"
    assert principal == [f"arn:aws:iam::{account}:root"], "the added statement must name the account root principal"
    assert added.get("Resource") == arn, "the added statement's Resource must be this topic"
    assert stmts["CustomOwnerGetAttributes"]["Action"] == "SNS:GetTopicAttributes", (
        "AddPermission must leave the custom statement unchanged"
    )

    sns.remove_permission(TopicArn=arn, Label=label)
    assert set(_statements(sns, arn)) == {"CustomOwnerGetAttributes"}, (
        f"RemovePermission must remove only its statement, got {sorted(_statements(sns, arn))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
