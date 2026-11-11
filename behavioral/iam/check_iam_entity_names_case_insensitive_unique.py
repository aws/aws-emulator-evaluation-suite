"""iam-entity-names-case-insensitive-unique."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-entity-names-case-insensitive-unique"
GROUP = "errors"
SERVICES = ["iam"]

_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
_POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _refused(ctx, fn, undo):
    """The (code, message) ``fn`` is refused with. An unexpected success registers ``undo`` for
    the entity it wrongly created, then raises naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    ctx.on_cleanup(_teardown(undo, "NoSuchEntity"))
    raise AssertionError(f"expected the case-swapped duplicate to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """User, role, group, managed policy and instance profile names are unique case-insensitively: a create
    differing only in case fails with EntityAlreadyExists and the exact message naming the requested
    spelling, Get by that spelling returns the original name and id, and the listing holds only it."""
    iam = ctx.client("iam")
    tail = uuid.uuid4().hex[:10]
    name = f"sim2real-behav-ci-Mixed{tail}"
    swapped = f"sim2real-behav-ci-mIXED{tail.swapcase()}"
    assert name != swapped and name.lower() == swapped.lower(), (name, swapped)
    path = f"/{ctx.unique_name('sim2real-behav-ci-')}/"

    # --- user ---
    user_id = iam.create_user(UserName=name, Path=path)["User"]["UserId"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_user(UserName=name), "NoSuchEntity"))
    code, msg = _refused(ctx, lambda: iam.create_user(UserName=swapped, Path=path),
                         lambda: iam.delete_user(UserName=swapped))
    assert code == "EntityAlreadyExists", f"CreateUser with a case-swapped name gave {code!r}"
    assert msg == f"User with name {swapped} already exists.", f"CreateUser message was {msg!r}"
    got = iam.get_user(UserName=swapped)["User"]
    assert (got["UserName"], got["UserId"]) == (name, user_id), (
        f"GetUser by the swapped name returned name {got['UserName']!r} and "
        f"{'the same' if got['UserId'] == user_id else 'a different'} id; expected the original"
    )
    users = [u["UserName"] for p in iam.get_paginator("list_users").paginate(PathPrefix=path) for u in p["Users"]]
    assert users == [name], f"ListUsers under the check's path returned {users!r}, expected only the original"

    # --- role ---
    role_id = iam.create_role(RoleName=name, Path=path, AssumeRolePolicyDocument=_TRUST)["Role"]["RoleId"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    code, msg = _refused(ctx, lambda: iam.create_role(RoleName=swapped, Path=path, AssumeRolePolicyDocument=_TRUST),
                         lambda: iam.delete_role(RoleName=swapped))
    assert code == "EntityAlreadyExists", f"CreateRole with a case-swapped name gave {code!r}"
    assert msg == f"Role with name {swapped} already exists.", f"CreateRole message was {msg!r}"
    got = iam.get_role(RoleName=swapped)["Role"]
    assert (got["RoleName"], got["RoleId"]) == (name, role_id), (
        f"GetRole by the swapped name returned name {got['RoleName']!r} and "
        f"{'the same' if got['RoleId'] == role_id else 'a different'} id; expected the original"
    )
    roles = [r["RoleName"] for p in iam.get_paginator("list_roles").paginate(PathPrefix=path) for r in p["Roles"]]
    assert roles == [name], f"ListRoles under the check's path returned {roles!r}, expected only the original"

    # --- group ---
    group_id = iam.create_group(GroupName=name, Path=path)["Group"]["GroupId"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_group(GroupName=name), "NoSuchEntity"))
    code, msg = _refused(ctx, lambda: iam.create_group(GroupName=swapped, Path=path),
                         lambda: iam.delete_group(GroupName=swapped))
    assert code == "EntityAlreadyExists", f"CreateGroup with a case-swapped name gave {code!r}"
    assert msg == f"Group with name {swapped} already exists.", f"CreateGroup message was {msg!r}"
    got = iam.get_group(GroupName=swapped)["Group"]
    assert (got["GroupName"], got["GroupId"]) == (name, group_id), (
        f"GetGroup by the swapped name returned name {got['GroupName']!r} and "
        f"{'the same' if got['GroupId'] == group_id else 'a different'} id; expected the original"
    )
    groups = [g["GroupName"] for p in iam.get_paginator("list_groups").paginate(PathPrefix=path) for g in p["Groups"]]
    assert groups == [name], f"ListGroups under the check's path returned {groups!r}, expected only the original"

    # --- customer managed policy ---
    policy = iam.create_policy(PolicyName=name, Path=path, PolicyDocument=_POLICY)["Policy"]
    policy_arn, policy_id = policy["Arn"], policy["PolicyId"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_policy(PolicyArn=policy_arn), "NoSuchEntity"))
    swapped_arn = f"arn:aws:iam::{ctx.account}:policy{path}{swapped}"
    code, msg = _refused(ctx, lambda: iam.create_policy(PolicyName=swapped, Path=path, PolicyDocument=_POLICY),
                         lambda: iam.delete_policy(PolicyArn=swapped_arn))
    assert code == "EntityAlreadyExists", f"CreatePolicy with a case-swapped name gave {code!r}"
    assert msg == f"A policy called {swapped} already exists. Duplicate names are not allowed.", (
        f"CreatePolicy message was {msg!r}"
    )
    got = iam.get_policy(PolicyArn=swapped_arn)["Policy"]
    assert (got["PolicyName"], got["PolicyId"]) == (name, policy_id), (
        f"GetPolicy by the swapped ARN returned name {got['PolicyName']!r} and "
        f"{'the same' if got['PolicyId'] == policy_id else 'a different'} id; expected the original"
    )
    policies = [
        q["PolicyName"]
        for p in iam.get_paginator("list_policies").paginate(Scope="Local", PathPrefix=path)
        for q in p["Policies"]
    ]
    assert policies == [name], f"ListPolicies under the check's path returned {policies!r}, expected only the original"

    # --- instance profile ---
    profile_id = iam.create_instance_profile(InstanceProfileName=name, Path=path)["InstanceProfile"][
        "InstanceProfileId"
    ]
    ctx.on_cleanup(_teardown(lambda: iam.delete_instance_profile(InstanceProfileName=name), "NoSuchEntity"))
    code, msg = _refused(ctx, lambda: iam.create_instance_profile(InstanceProfileName=swapped, Path=path),
                         lambda: iam.delete_instance_profile(InstanceProfileName=swapped))
    assert code == "EntityAlreadyExists", f"CreateInstanceProfile with a case-swapped name gave {code!r}"
    assert msg == f"Instance Profile {swapped} already exists.", f"CreateInstanceProfile message was {msg!r}"
    got = iam.get_instance_profile(InstanceProfileName=swapped)["InstanceProfile"]
    assert (got["InstanceProfileName"], got["InstanceProfileId"]) == (name, profile_id), (
        f"GetInstanceProfile by the swapped name returned name {got['InstanceProfileName']!r} and "
        f"{'the same' if got['InstanceProfileId'] == profile_id else 'a different'} id; expected the original"
    )
    profiles = [
        i["InstanceProfileName"]
        for p in iam.get_paginator("list_instance_profiles").paginate(PathPrefix=path)
        for i in p["InstanceProfiles"]
    ]
    assert profiles == [name], (
        f"ListInstanceProfiles under the check's path returned {profiles!r}, expected only the original"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
