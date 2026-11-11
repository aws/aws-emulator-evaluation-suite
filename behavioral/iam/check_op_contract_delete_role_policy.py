"""op-contract-deleteRolePolicy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteRolePolicy"
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
_INLINE_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRolePolicy removes the inline policy; NoSuchEntity on an unknown policy name."""
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-role-rp-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "inline-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(_INLINE_DOC))
    names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert policy_name in names, f"expected {policy_name!r} in {names!r} after put_role_policy"

    # success path
    resp = iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from DeleteRolePolicy, got {status}"
    names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert policy_name not in names, f"expected {policy_name!r} gone from {names!r} after delete"
    code, code_msg = _client_error(lambda: iam.get_role_policy(RoleName=role_name, PolicyName=policy_name))
    assert code == "NoSuchEntity", f"expected policy gone, got {code}"
    assert code_msg == f"The role policy with name {policy_name} cannot be found.", f"unexpected error message {code_msg!r}"

    # error boundary: deleting an unknown policy name on an existing role
    code2, code2_msg = _client_error(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="never-existed"))
    assert code2 == "NoSuchEntity", f"expected NoSuchEntity, got {code2}"
    assert code2_msg == "The role policy with name never-existed cannot be found.", f"unexpected error message {code2_msg!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
