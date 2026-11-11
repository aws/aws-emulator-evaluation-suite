"""delete-policy-while-attached."""
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

CHECK = "delete-policy-while-attached"
GROUP = 'errors'
SERVICES = ['iam']

ERR_DELETE_CONFLICT = "DeleteConflict"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected the call to raise, but it succeeded")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicy while attached to a role raises DeleteConflict, the policy
    survives intact and still attached, and once detached the identical delete
    succeeds and the policy is gone."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"),
        PolicyDocument=MINIMAL_POLICY_DOCUMENT,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: _safe(lambda: iam.delete_policy(PolicyArn=a)))
    iam.attach_role_policy(RoleName=role, PolicyArn=arn)
    ctx.on_cleanup(lambda r=role, p=arn: _safe(lambda: iam.detach_role_policy(RoleName=r, PolicyArn=p)))

    # Break exactly one thing: try to delete a policy that is still attached.
    code, message = _error_code(lambda: iam.delete_policy(PolicyArn=arn))
    assert code == ERR_DELETE_CONFLICT, f"Expected {ERR_DELETE_CONFLICT}, got {code!r}"
    assert message == "Cannot delete a policy attached to entities.", (
        f"expected the exact DeleteConflict message AWS returns, got {message!r}"
    )

    # Effect absent: an independent read shows the policy survives, still attached.
    still_there = iam.get_policy(PolicyArn=arn)["Policy"]
    assert still_there["Arn"] == arn, f"Expected policy {arn} to still exist, got {still_there!r}"
    attached = iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]
    assert any(p["PolicyArn"] == arn for p in attached), (
        f"Expected {arn} to remain attached to {role}, got {attached!r}"
    )

    # Restore: detach, then the identical delete call succeeds.
    iam.detach_role_policy(RoleName=role, PolicyArn=arn)
    iam.delete_policy(PolicyArn=arn)
    gone_code, gone_message = _error_code(lambda: iam.get_policy(PolicyArn=arn))
    assert gone_code == ERR_NO_SUCH_ENTITY, f"Expected {ERR_NO_SUCH_ENTITY}, got {gone_code!r}"
    assert gone_message == f"Policy {still_there['Arn']} was not found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
