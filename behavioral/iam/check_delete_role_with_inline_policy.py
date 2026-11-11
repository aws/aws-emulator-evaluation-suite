"""delete-role-with-inline-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

MINIMAL_TRUST_POLICY = json.dumps(
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

CHECK = "delete-role-with-inline-policy"
GROUP = 'errors'
SERVICES = ['iam']

MINIMAL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:GetUser",
                "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
            }
        ],
    }
)

ERR_DELETE_CONFLICT = "DeleteConflict"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _best_effort_delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != ERR_NO_SUCH_ENTITY:
            raise


def _best_effort_delete_role_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != ERR_NO_SUCH_ENTITY:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRole succeeds on an unencumbered role (positive control); while an inline policy
    exists on a role it raises DeleteConflict and both the role and the policy survive; once the
    inline policy is removed the identical delete call succeeds."""
    iam = ctx.client("iam")

    # Positive control: an unencumbered role deletes cleanly, so a target that rejects every
    # DeleteRole cannot be mistaken for one that specifically enforces the inline-policy rule.
    control_role = ctx.unique_name("sim2real-behav-role-ctrl-")
    iam.create_role(RoleName=control_role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=control_role: _best_effort_delete_role(iam, n))
    iam.delete_role(RoleName=control_role)
    control_err = _client_error(lambda: iam.get_role(RoleName=control_role))
    assert control_err.get("Code") == ERR_NO_SUCH_ENTITY, (
        f"expected {ERR_NO_SUCH_ENTITY} for the deleted control role, got {control_err.get('Code')!r}"
    )
    assert control_err.get("Message") == f"The role with name {control_role} cannot be found.", (
        f'expected the exact NoSuchEntity message AWS returns, got {control_err.get("Message")!r}'
    )

    # Break exactly one thing: attach an inline policy, then try the same delete.
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role: _best_effort_delete_role(iam, n))
    iam.put_role_policy(RoleName=role, PolicyName="blocker", PolicyDocument=MINIMAL_POLICY_DOCUMENT)
    ctx.on_cleanup(lambda r=role, n="blocker": _best_effort_delete_role_policy(iam, r, n))

    conflict_err = _client_error(lambda: iam.delete_role(RoleName=role))
    assert conflict_err.get("Code") == ERR_DELETE_CONFLICT, (
        f"expected {ERR_DELETE_CONFLICT} while an inline policy exists, got {conflict_err.get('Code')!r}"
    )
    assert conflict_err.get("Message") == "Cannot delete entity, must delete policies first.", (
        f'expected the exact DeleteConflict message AWS returns, got {conflict_err.get("Message")!r}'
    )

    # Effect absent: the role and its inline policy both survive the rejected delete.
    survived = iam.get_role(RoleName=role)["Role"]
    assert survived["RoleName"] == role, "role should still exist after the rejected delete"
    remaining_policies = iam.list_role_policies(RoleName=role)["PolicyNames"]
    assert "blocker" in remaining_policies, "inline policy should still be attached after the rejected delete"

    # Restore, then the identical delete call succeeds.
    iam.delete_role_policy(RoleName=role, PolicyName="blocker")
    iam.delete_role(RoleName=role)
    gone_err = _client_error(lambda: iam.get_role(RoleName=role))
    assert gone_err.get("Code") == ERR_NO_SUCH_ENTITY, (
        f"expected {ERR_NO_SUCH_ENTITY} after removing the inline policy and deleting, got {gone_err.get('Code')!r}"
    )
    assert gone_err.get("Message") == f"The role with name {survived['RoleName']} cannot be found.", (
        f'expected the exact NoSuchEntity message AWS returns, got {gone_err.get("Message")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
