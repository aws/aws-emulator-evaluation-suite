"""delete-policy-conflict-while-attached-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-policy-conflict-while-attached-rejected"
GROUP = "errors"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A customer-managed policy that is still attached to a role cannot be
    deleted (DeleteConflictException); the policy remains attached and intact
    until it is detached, at which point the same delete succeeds."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    policy_name = ctx.unique_name("sim2real-behav-policy-")

    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    policy_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_policy(PolicyArn=policy_arn)))

    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))

    # Break exactly one thing: try to delete a policy that is still attached.
    code, message = _error(lambda: iam.delete_policy(PolicyArn=policy_arn))
    assert code == "DeleteConflict", f"expected DeleteConflict deleting an attached policy, got {code!r}"
    expected = "Cannot delete a policy attached to entities."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # Effect absent: the policy still exists, and is still attached to the role.
    still_there = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    assert still_there["Arn"] == policy_arn, (
        f"policy {policy_arn} must still exist after the rejected delete, got {still_there!r}"
    )
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    assert any(p["PolicyArn"] == policy_arn for p in attached), (
        f"policy {policy_arn} must remain attached to {role_name} after the rejected delete, "
        f"got {attached!r}"
    )

    # Restore: once detached, the identical delete call now succeeds.
    iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.delete_policy(PolicyArn=policy_arn)
    final_code, final_message = _error(lambda: iam.get_policy(PolicyArn=policy_arn))
    assert final_code == "NoSuchEntity", (
        f"expected the policy to be gone after detach+delete, got {final_code!r}"
    )
    expected_gone = f"Policy {policy_arn} was not found."
    assert final_message == expected_gone, f"expected message {expected_gone!r}, got {final_message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
