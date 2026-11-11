"""role-delete-with-attached-policy-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-delete-with-attached-policy-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

_TRUST_POLICY = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
    '"Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
)
_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRole must be rejected with DeleteConflict while a managed policy is
    still attached to the role, and the identical DeleteRole call must succeed
    once that policy is detached."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-roledelconflict-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))

    iam.attach_role_policy(RoleName=role_name, PolicyArn=_MANAGED_POLICY_ARN)
    ctx.on_cleanup(
        lambda: _best_effort_detach(iam, role_name, _MANAGED_POLICY_ARN)
    )

    code, message = _expect_error(lambda: iam.delete_role(RoleName=role_name))
    assert code == "DeleteConflict", (
        f"expected DeleteConflict while a policy is attached, got {code}"
    )
    want = "Cannot delete entity, must detach all policies first."
    assert message == want, f"DeleteConflict message: expected {want!r}, got {message!r}"

    # role and the attachment must still be intact since the delete was rejected
    got = iam.get_role(RoleName=role_name)["Role"]
    assert got["RoleName"] == role_name

    attached = {
        p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    }
    assert _MANAGED_POLICY_ARN in attached, (
        f"expected {_MANAGED_POLICY_ARN} still attached after the rejected delete, got {attached}"
    )

    # once the blocking policy is detached, the identical DeleteRole call succeeds
    iam.detach_role_policy(RoleName=role_name, PolicyArn=_MANAGED_POLICY_ARN)
    iam.delete_role(RoleName=role_name)
    gone_code, gone_message = _expect_error(lambda: iam.get_role(RoleName=role_name))
    assert gone_code == "NoSuchEntity", f"expected role gone after delete, got {gone_code}"
    want = f"The role with name {role_name} cannot be found."
    assert gone_message == want, f"NoSuchEntity message: expected {want!r}, got {gone_message!r}"


def _expect_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_detach(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
