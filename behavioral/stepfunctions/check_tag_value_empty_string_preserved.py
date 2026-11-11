"""tag-value-empty-string-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "tag-value-empty-string-preserved"
GROUP = "representation"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An empty-string tag value reads back from ListTagsForResource as "" (not dropped or null),
    and UntagResource removes that key entirely without disturbing the other tag."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role_for_state_machine(ctx)

    definition = json.dumps(
        {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    )
    sm_name = ctx.unique_name("sim2real-sfn-emptytag-")
    resource_arn = sfn.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)[
        "stateMachineArn"
    ]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=resource_arn))

    sfn.tag_resource(
        resourceArn=resource_arn,
        tags=[
            {"key": "empty-value-tag", "value": ""},
            {"key": "non-empty-tag", "value": "present"},
        ],
    )

    tags_now = sfn.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    by_key = {t["key"]: t for t in tags_now}

    assert "empty-value-tag" in by_key, (
        f"empty-value tag was dropped entirely, got keys {sorted(by_key)}"
    )
    assert by_key["empty-value-tag"]["value"] == "", (
        f"expected empty string preserved, got {by_key['empty-value-tag']['value']!r}"
    )
    assert by_key["non-empty-tag"]["value"] == "present", (
        f"expected 'present', got {by_key['non-empty-tag']['value']!r}"
    )

    sfn.untag_resource(resourceArn=resource_arn, tagKeys=["empty-value-tag"])
    tags_after_untag = sfn.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    by_key_after = {t["key"]: t for t in tags_after_untag}

    assert "empty-value-tag" not in by_key_after, (
        f"untag_resource did not remove the empty-value tag, still present: "
        f"{by_key_after.get('empty-value-tag')!r}"
    )
    assert by_key_after["non-empty-tag"]["value"] == "present", (
        f"untagging one key disturbed the other, got {by_key_after.get('non-empty-tag')!r}"
    )


def _create_role_for_state_machine(ctx) -> str:
    iam = ctx.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_name = ctx.unique_name("sim2real-sfn-emptyrole-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
