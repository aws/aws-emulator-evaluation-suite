"""op-contract-deleteRole."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteRole"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRole removes an unencumbered role, and a mutation on the dead id still fails;
    DeleteConflict while an inline policy remains, the role survives the rejected delete, and
    the identical delete succeeds once the dependent is removed."""
    iam = ctx.client("iam")

    # success path
    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY))
    assert role_name in [r["RoleName"] for r in _listed(iam, "list_roles", "Roles")]
    resp = iam.delete_role(RoleName=role_name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    # substantive state check: the role is actually gone from the account's role list,
    # not merely that the call returned 200
    remaining_names = [r["RoleName"] for r in _listed(iam, "list_roles", "Roles")]
    assert role_name not in remaining_names, "deleted role still present in ListRoles"
    code, code_msg = _client_error(lambda: iam.get_role(RoleName=role_name))
    assert code == "NoSuchEntity", f"expected role gone, got {code}"
    assert code_msg == f"The role with name {role_name} cannot be found.", f"unexpected error message {code_msg!r}"
    # a mutation on the dead id must also fail, not merely a read
    mutation_code, mutation_code_msg = _client_error(
        lambda: iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(_TRUST_POLICY))
    )
    assert mutation_code == "NoSuchEntity", f"mutating a deleted role should fail NoSuchEntity, got {mutation_code}"
    assert mutation_code_msg == f"The role with name {role_name} cannot be found.", f"unexpected error message {mutation_code_msg!r}"

    # error boundary: role with an inline policy still attached cannot be deleted
    conflict_role = ctx.unique_name("sim2real-behav-role-conflict-")
    iam.create_role(RoleName=conflict_role, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY))
    iam.put_role_policy(
        RoleName=conflict_role,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=conflict_role, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=conflict_role)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    conflict_code, conflict_code_msg = _client_error(lambda: iam.delete_role(RoleName=conflict_role))
    assert conflict_code == "DeleteConflict", f"expected DeleteConflict, got {conflict_code}"
    assert conflict_code_msg == "Cannot delete entity, must delete policies first.", f"unexpected error message {conflict_code_msg!r}"
    # effect-absent: the rejected delete must not have removed the role
    survived = iam.get_role(RoleName=conflict_role)["Role"]
    assert survived["RoleName"] == conflict_role, "role should survive a rejected delete"

    # restore: once the dependent is gone, the identical delete call succeeds
    iam.delete_role_policy(RoleName=conflict_role, PolicyName="inline")
    iam.delete_role(RoleName=conflict_role)
    restored_code, restored_code_msg = _client_error(lambda: iam.get_role(RoleName=conflict_role))
    assert restored_code == "NoSuchEntity", f"expected role gone after restore+delete, got {restored_code}"
    assert restored_code_msg == f"The role with name {conflict_role} cannot be found.", f"unexpected error message {restored_code_msg!r}"
    # and a second delete on that now-dead id fails too
    redelete_code, redelete_code_msg = _client_error(lambda: iam.delete_role(RoleName=conflict_role))
    assert redelete_code == "NoSuchEntity", f"double-delete on dead role should fail NoSuchEntity, got {redelete_code}"
    assert redelete_code_msg == f"The role with name {conflict_role} cannot be found.", f"unexpected error message {redelete_code_msg!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _listed(iam, operation, key):
    """Every item an IAM listing returns, across all pages."""
    return [item for page in iam.get_paginator(operation).paginate() for item in page[key]]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
