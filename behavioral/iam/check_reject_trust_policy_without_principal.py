"""reject-trust-policy-without-principal."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-trust-policy-without-principal"
GROUP = 'overly-permissive'
SERVICES = ['iam']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRole rejects a trust policy with no Principal as MalformedPolicyDocument and stores no
    role, while the same policy with a Principal succeeds (so not every CreateRole is refused).
    """
    iam = ctx.client("iam")

    control_role = ctx.unique_name("sim2real-behav-iam-hasprincipal-role-")
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, control_role))
    control_doc = json.dumps(
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
    iam.create_role(
        RoleName=control_role,
        AssumeRolePolicyDocument=control_doc,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    fetched = iam.get_role(RoleName=control_role)["Role"]["RoleName"]
    assert fetched == control_role, (
        f"control role with a valid Principal must be creatable and independently readable "
        f"afterwards; get_role returned RoleName={fetched!r}"
    )

    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}],
        }
    )
    role_name = ctx.unique_name("sim2real-behav-iam-noprincipal-role-")
    # Registered in case the create is wrongly accepted, so the role does not leak.
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, role_name))

    code, message = _error_code(
        lambda: iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=doc,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )
    assert code == "MalformedPolicyDocument", (
        f"expected MalformedPolicyDocument for a trust policy with no "
        f"Principal, got {code}"
    )
    expected = "Missing required field Principal"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code2, message2 = _error_code(lambda: iam.get_role(RoleName=role_name))
    assert code2 == "NoSuchEntity", (
        f"role must not exist after a rejected create, got {code2}"
    )
    expected = f"The role with name {role_name} cannot be found."
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"


def _error_code(fn):
    """The (error code, message) fn() raises; an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_role_if_exists(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
