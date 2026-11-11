"""op-contract-listRolePolicies-single-inline."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listRolePolicies-single-inline"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
)
_INLINE_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}]}
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Success path lists exactly the inline policy names put on the role; a missing role yields NoSuchEntityException."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch09-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_name = "sim2real-batch09-inline"
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_name, PolicyDocument=_INLINE_DOC)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name))

    resp = iam.list_role_policies(RoleName=role_name)
    assert resp["PolicyNames"] == [inline_name], f"expected exactly [{inline_name}], got {resp['PolicyNames']}"
    assert resp["IsTruncated"] is False

    # Error boundary: RoleName that does not exist.
    bogus_role = ctx.unique_name("sim2real-batch09-missing-role-")
    code, message = _error(lambda: iam.list_role_policies(RoleName=bogus_role))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The role with name {bogus_role} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
