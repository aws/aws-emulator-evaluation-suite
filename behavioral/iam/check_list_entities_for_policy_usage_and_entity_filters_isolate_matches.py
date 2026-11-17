"""list-entities-for-policy-usage-and-entity-filters-isolate-matches."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-entities-for-policy-usage-and-entity-filters-isolate-matches"
GROUP = "policy-attachments"
SERVICES = ["iam"]

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
)
_POLICY_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}]}
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEntitiesForPolicy's PolicyUsageFilter separates a role that holds the policy as its
    permissions boundary from one that holds it as an attached permissions policy, and
    EntityFilter restricts the response to one entity type at a time.
    """
    iam = ctx.client("iam")

    policy_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-lefp-pol-"),
        PolicyDocument=_POLICY_DOC,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    attached_role = ctx.unique_name("sim2real-behav-lefp-attached-")
    iam.create_role(RoleName=attached_role, AssumeRolePolicyDocument=_TRUST_POLICY)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=attached_role))
    iam.attach_role_policy(RoleName=attached_role, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=attached_role, PolicyArn=policy_arn))

    bounded_role = ctx.unique_name("sim2real-behav-lefp-bounded-")
    iam.create_role(
        RoleName=bounded_role, AssumeRolePolicyDocument=_TRUST_POLICY, PermissionsBoundary=policy_arn
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bounded_role))

    group_name = ctx.unique_name("sim2real-behav-lefp-group-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))
    iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn))

    as_policy = iam.list_entities_for_policy(PolicyArn=policy_arn, PolicyUsageFilter="PermissionsPolicy")
    assert {r["RoleName"] for r in as_policy["PolicyRoles"]} == {attached_role}, (
        f"PolicyUsageFilter=PermissionsPolicy must list only the attached role, "
        f"got {[r['RoleName'] for r in as_policy['PolicyRoles']]!r}"
    )
    assert {g["GroupName"] for g in as_policy["PolicyGroups"]} == {group_name}, (
        f"PolicyUsageFilter=PermissionsPolicy must list the attached group, "
        f"got {[g['GroupName'] for g in as_policy['PolicyGroups']]!r}"
    )
    assert as_policy["PolicyUsers"] == [], f"expected no users, got {as_policy['PolicyUsers']!r}"

    as_boundary = iam.list_entities_for_policy(PolicyArn=policy_arn, PolicyUsageFilter="PermissionsBoundary")
    assert {r["RoleName"] for r in as_boundary["PolicyRoles"]} == {bounded_role}, (
        f"PolicyUsageFilter=PermissionsBoundary must list only the bounded role, "
        f"got {[r['RoleName'] for r in as_boundary['PolicyRoles']]!r}"
    )
    assert as_boundary["PolicyGroups"] == [], f"expected no groups as a boundary user, got {as_boundary['PolicyGroups']!r}"
    assert as_boundary["PolicyUsers"] == [], f"expected no users as a boundary user, got {as_boundary['PolicyUsers']!r}"

    role_filtered = iam.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter="Role")
    assert {r["RoleName"] for r in role_filtered["PolicyRoles"]} == {attached_role, bounded_role}, (
        f"EntityFilter=Role must list both roles regardless of usage, "
        f"got {[r['RoleName'] for r in role_filtered['PolicyRoles']]!r}"
    )
    assert role_filtered["PolicyGroups"] == [], f"EntityFilter=Role must exclude groups, got {role_filtered['PolicyGroups']!r}"
    assert role_filtered["PolicyUsers"] == [], f"EntityFilter=Role must exclude users, got {role_filtered['PolicyUsers']!r}"

    group_filtered = iam.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter="Group")
    assert {g["GroupName"] for g in group_filtered["PolicyGroups"]} == {group_name}, (
        f"EntityFilter=Group must list the attached group, "
        f"got {[g['GroupName'] for g in group_filtered['PolicyGroups']]!r}"
    )
    assert group_filtered["PolicyRoles"] == [], f"EntityFilter=Group must exclude roles, got {group_filtered['PolicyRoles']!r}"
    assert group_filtered["PolicyUsers"] == [], f"EntityFilter=Group must exclude users, got {group_filtered['PolicyUsers']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
