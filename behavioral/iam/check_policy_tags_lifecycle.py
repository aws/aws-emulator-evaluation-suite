"""policy-tags-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "policy-tags-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tagging a managed policy makes tags visible via ListPolicyTags;
    untagging removes them."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-policy-")
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    created = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(doc))
    arn = created["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=arn))

    initial = iam.list_policy_tags(PolicyArn=arn)["Tags"]
    assert initial == [], f"expected no tags before TagPolicy, got {initial}"

    tags = [{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "platform"}]
    iam.tag_policy(PolicyArn=arn, Tags=tags)

    listed = iam.list_policy_tags(PolicyArn=arn)["Tags"]
    assert {(t["Key"], t["Value"]) for t in listed} == {(t["Key"], t["Value"]) for t in tags}, (
        f"expected tags {tags}, got {listed}"
    )

    iam.untag_policy(PolicyArn=arn, TagKeys=["env", "owner"])
    after = iam.list_policy_tags(PolicyArn=arn)["Tags"]
    assert after == [], f"expected tags removed after UntagPolicy, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
