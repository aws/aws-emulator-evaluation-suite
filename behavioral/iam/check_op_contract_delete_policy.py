"""op-contract-deletePolicy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deletePolicy"
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
_PERMISSIONS_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicy removes an unattached managed policy, and a re-delete of the same now-dead
    ARN also fails; DeleteConflict while still attached, the policy stays intact and attached
    until detached, at which point the identical delete call succeeds."""
    iam = ctx.client("iam")

    # success path
    policy_name = ctx.unique_name("sim2real-behav-pol-")
    arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(_PERMISSIONS_DOC),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    resp = iam.delete_policy(PolicyArn=arn)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected DeletePolicy to return HTTP 200, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    code, message = _error(lambda: iam.get_policy(PolicyArn=arn))
    assert code == "NoSuchEntity", f"expected policy gone, got {code}"
    expected_gone = f"Policy {arn} was not found."
    assert message == expected_gone, f"expected message {expected_gone!r}, got {message!r}"
    # a mutation on the now-dead id fails too, not just the read
    redelete_code, redelete_message = _error(lambda: iam.delete_policy(PolicyArn=arn))
    assert redelete_code == "NoSuchEntity", (
        f"expected re-delete of an already-gone policy to fail NoSuchEntity, got {redelete_code}"
    )
    expected_redelete = f"Policy {arn} was not found."
    assert redelete_message == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_message!r}"
    )

    # error boundary: policy still attached to a role cannot be deleted
    conflict_name = ctx.unique_name("sim2real-behav-pol-conflict-")
    conflict_arn = iam.create_policy(
        PolicyName=conflict_name,
        PolicyDocument=json.dumps(_PERMISSIONS_DOC),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    role_name = ctx.unique_name("sim2real-behav-role-for-pol-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=conflict_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=conflict_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_policy(PolicyArn=conflict_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    conflict_code, conflict_message = _error(lambda: iam.delete_policy(PolicyArn=conflict_arn))
    assert conflict_code == "DeleteConflict", f"expected DeleteConflict, got {conflict_code}"
    expected_conflict = "Cannot delete a policy attached to entities."
    assert conflict_message == expected_conflict, (
        f"expected message {expected_conflict!r}, got {conflict_message!r}"
    )

    # effect absent: the refused delete left the policy intact and still attached
    still_there = iam.get_policy(PolicyArn=conflict_arn)["Policy"]
    assert still_there["Arn"] == conflict_arn, (
        f"expected the refused delete to leave the policy in place, got {still_there}"
    )
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    assert any(p["PolicyArn"] == conflict_arn for p in attached), (
        f"expected {conflict_arn} to remain attached to {role_name} after the refused delete, got {attached}"
    )

    # restore: once detached, the identical delete call now succeeds
    iam.detach_role_policy(RoleName=role_name, PolicyArn=conflict_arn)
    iam.delete_policy(PolicyArn=conflict_arn)
    restored_code, restored_message = _error(lambda: iam.get_policy(PolicyArn=conflict_arn))
    assert restored_code == "NoSuchEntity", (
        f"expected the identical delete to succeed once detached, but the policy is still readable "
        f"(get_policy did not fail NoSuchEntity: {restored_code})"
    )
    expected_restored = f"Policy {conflict_arn} was not found."
    assert restored_message == expected_restored, (
        f"expected message {expected_restored!r}, got {restored_message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
