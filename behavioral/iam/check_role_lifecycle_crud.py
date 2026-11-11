"""role-lifecycle-crud."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-lifecycle-crud"
GROUP = 'role_lifecycle'
SERVICES = ['iam']

TRUST_POLICY_EC2 = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

TRUST_POLICY_LAMBDA = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _err(fn):
    """The ClientError's (code, message); a successful call fails the refusal claim."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call succeeded where AWS refuses it and returned {result!r}")


def _delete_role_if_present(iam, role_name):
    """Teardown: the body deletes the role itself, so only a role it left behind is removed."""
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _poll_until(probe, predicate, timeout_s=20.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _role_names(iam, path_prefix):
    pages = iam.get_paginator("list_roles").paginate(PathPrefix=path_prefix)
    return [r["RoleName"] for page in pages for r in page["Roles"]]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """State machine: CreateRole -> active (GetRole/ListRoles reflect it) -> UpdateRole
    (description+session duration) -> UpdateRoleDescription (legacy single-field update) ->
    UpdateAssumeRolePolicy (trust doc swap) -> DeleteRole -> absent."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    path = f"/sim2real/{role_name}/"
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=TRUST_POLICY_EC2,
        Description="initial description",
        Path=path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_id = created["Role"]["RoleId"]
    ctx.on_cleanup(lambda: _delete_role_if_present(iam, role_name))

    got = iam.get_role(RoleName=role_name)
    assert got["Role"]["RoleId"] == role_id, (
        f"expected RoleId {role_id!r} on GetRole, got {got['Role']['RoleId']!r}"
    )
    assert got["Role"]["Description"] == "initial description", (
        f"expected initial description, got {got['Role']['Description']!r}"
    )
    # ListRoles is eventually consistent with respect to a just-created role; wait for it
    # to reflect the create rather than assuming a fixed settle time.
    names = _poll_until(
        lambda: _role_names(iam, path),
        lambda names: role_name in names,
    )
    assert role_name in names, f"newly created role missing from ListRoles: {names}"

    iam.update_role(RoleName=role_name, Description="updated via UpdateRole", MaxSessionDuration=7200)
    got2 = iam.get_role(RoleName=role_name)
    assert got2["Role"]["Description"] == "updated via UpdateRole", (
        f"expected description updated via UpdateRole, got {got2['Role']['Description']!r}"
    )
    assert got2["Role"]["MaxSessionDuration"] == 7200, (
        f"expected MaxSessionDuration 7200, got {got2['Role']['MaxSessionDuration']!r}"
    )

    iam.update_role_description(RoleName=role_name, Description="updated via UpdateRoleDescription")
    got3 = iam.get_role(RoleName=role_name)
    assert got3["Role"]["Description"] == "updated via UpdateRoleDescription", (
        f"expected description updated via UpdateRoleDescription, got {got3['Role']['Description']!r}"
    )

    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=TRUST_POLICY_LAMBDA)
    got4 = iam.get_role(RoleName=role_name)
    principal = got4["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Service"]
    assert principal == "lambda.amazonaws.com", f"expected updated trust principal, got {principal}"

    iam.delete_role(RoleName=role_name)
    gone = f"The role with name {role_name} cannot be found."
    code, message = _err(lambda: iam.get_role(RoleName=role_name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity from GetRole on deleted role, got {code!r}"
    assert message == gone, f"GetRole NoSuchEntity message: expected {gone!r}, got {message!r}"

    # A mutation on the dead role must also fail with the same specific not-found code,
    # not merely a read.
    mutate_code, mutate_message = _err(
        lambda: iam.update_role_description(RoleName=role_name, Description="post-delete")
    )
    assert mutate_code == "NoSuchEntity", (
        f"expected NoSuchEntity from UpdateRoleDescription on deleted role, got {mutate_code!r}"
    )
    assert mutate_message == gone, (
        f"UpdateRoleDescription NoSuchEntity message: expected {gone!r}, got {mutate_message!r}"
    )

    # ListRoles is eventually consistent with respect to a just-deleted role; wait for it
    # to reflect the delete rather than assuming a fixed settle time.
    names_after = _poll_until(
        lambda: _role_names(iam, path),
        lambda names: role_name not in names,
    )
    assert role_name not in names_after, "deleted role still present in ListRoles"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
