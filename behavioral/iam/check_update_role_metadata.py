"""update-role-metadata."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-role-metadata"
GROUP = "state-machine"
SERVICES = ["iam"]

_TRUST_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRole and UpdateRoleDescription mutate description/session-duration in place while
    Arn/RoleId/CreateDate stay fixed, and the change is visible on the next GetRole."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-rmeta-")

    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_DOC,
        Description="initial description",
        MaxSessionDuration=3600,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    role_arn = created["Arn"]
    role_id = created["RoleId"]
    create_date = created["CreateDate"]
    # Real IAM's CreateRole response does not reliably echo back "Description" or
    # "MaxSessionDuration" (they are subject to eventual consistency and may be omitted from the
    # immediate create response even though they were supplied on the request), so verify both via
    # a bounded GetRole poll instead of the create response.
    initial_role = _poll_get_role(
        iam,
        role_name,
        lambda r: r.get("Description") == "initial description" and r.get("MaxSessionDuration") == 3600,
        "GetRole to reflect the CreateRole description/session-duration",
    )
    assert initial_role["Description"] == "initial description", (
        f"expected Description='initial description' after CreateRole, got {initial_role.get('Description')!r}"
    )
    assert initial_role["MaxSessionDuration"] == 3600, (
        f"expected MaxSessionDuration=3600 after CreateRole, got {initial_role.get('MaxSessionDuration')!r}"
    )

    iam.update_role(RoleName=role_name, Description="updated via UpdateRole", MaxSessionDuration=7200)

    after_update_role = _poll_get_role(
        iam,
        role_name,
        lambda r: r["Description"] == "updated via UpdateRole",
        "GetRole to reflect UpdateRole",
    )
    assert after_update_role["Description"] == "updated via UpdateRole", (
        f"expected Description='updated via UpdateRole' after UpdateRole, got {after_update_role['Description']!r}"
    )
    assert after_update_role["MaxSessionDuration"] == 7200, (
        f"expected MaxSessionDuration=7200 after UpdateRole, got {after_update_role['MaxSessionDuration']!r}"
    )
    assert after_update_role["Arn"] == role_arn, (
        f"Arn must stay fixed across UpdateRole: expected {role_arn!r}, got {after_update_role['Arn']!r}"
    )
    assert after_update_role["RoleId"] == role_id, (
        f"RoleId must stay fixed across UpdateRole: expected {role_id!r}, got {after_update_role['RoleId']!r}"
    )
    assert after_update_role["CreateDate"] == create_date, (
        f"CreateDate must stay fixed across UpdateRole: expected {create_date!r}, got {after_update_role['CreateDate']!r}"
    )

    resp = iam.update_role_description(RoleName=role_name, Description="updated via UpdateRoleDescription")
    assert resp["Role"]["Description"] == "updated via UpdateRoleDescription", (
        f"UpdateRoleDescription response should echo the new description, got {resp['Role']['Description']!r}"
    )

    after_update_desc = _poll_get_role(
        iam,
        role_name,
        lambda r: r["Description"] == "updated via UpdateRoleDescription",
        "GetRole to reflect UpdateRoleDescription",
    )
    assert after_update_desc["Description"] == "updated via UpdateRoleDescription", (
        f"expected Description='updated via UpdateRoleDescription', got {after_update_desc['Description']!r}"
    )
    # UpdateRoleDescription must not have reverted the previously set MaxSessionDuration.
    assert after_update_desc["MaxSessionDuration"] == 7200, (
        f"UpdateRoleDescription must not revert MaxSessionDuration: expected 7200, got {after_update_desc['MaxSessionDuration']!r}"
    )
    assert after_update_desc["Arn"] == role_arn, (
        f"Arn must stay fixed across UpdateRoleDescription: expected {role_arn!r}, got {after_update_desc['Arn']!r}"
    )
    assert after_update_desc["RoleId"] == role_id, (
        f"RoleId must stay fixed across UpdateRoleDescription: expected {role_id!r}, got {after_update_desc['RoleId']!r}"
    )
    assert after_update_desc["CreateDate"] == create_date, (
        f"CreateDate must stay fixed across UpdateRoleDescription: expected {create_date!r}, got {after_update_desc['CreateDate']!r}"
    )


def _poll_get_role(iam, role_name, predicate, description, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    role = None
    while time.monotonic() < deadline:
        role = iam.get_role(RoleName=role_name)["Role"]
        if predicate(role):
            return role
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last GetRole returned {role!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
