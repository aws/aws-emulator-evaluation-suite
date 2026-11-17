"""list-policies-only-attached-excludes-unattached-customer-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-policies-only-attached-excludes-unattached-customer-policy"
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
    """ListPolicies(OnlyAttached=True) excludes a customer managed policy with no attachment and
    includes one attached to a role, both scoped by a shared PathPrefix.
    """
    iam = ctx.client("iam")
    path = f"/{ctx.unique_name('sim2real-behav-loa')}/"

    unattached_name = ctx.unique_name("sim2real-behav-loa-unattached-")
    unattached_arn = iam.create_policy(
        PolicyName=unattached_name,
        PolicyDocument=_POLICY_DOC,
        Path=path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=unattached_arn))

    attached_name = ctx.unique_name("sim2real-behav-loa-attached-")
    attached_arn = iam.create_policy(
        PolicyName=attached_name,
        PolicyDocument=_POLICY_DOC,
        Path=path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=attached_arn))

    role_name = ctx.unique_name("sim2real-behav-loa-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=attached_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=attached_arn))

    unfiltered = iam.list_policies(Scope="Local", PathPrefix=path)["Policies"]
    unfiltered_names = {p["PolicyName"] for p in unfiltered}
    assert unfiltered_names == {unattached_name, attached_name}, (
        f"expected both policies without OnlyAttached, got {unfiltered_names!r}"
    )

    only_attached = iam.list_policies(Scope="Local", PathPrefix=path, OnlyAttached=True)["Policies"]
    only_attached_names = {p["PolicyName"] for p in only_attached}
    assert only_attached_names == {attached_name}, (
        f"OnlyAttached=True must exclude the unattached policy, got {only_attached_names!r}"
    )

    iam.detach_role_policy(RoleName=role_name, PolicyArn=attached_arn)
    after_detach = iam.list_policies(Scope="Local", PathPrefix=path, OnlyAttached=True)["Policies"]
    assert after_detach == [], (
        f"OnlyAttached=True must drop a policy the moment its last attachment is removed, got {after_detach!r}"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=attached_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
