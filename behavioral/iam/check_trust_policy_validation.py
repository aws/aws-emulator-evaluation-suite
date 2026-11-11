"""trust-policy-validation."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

CHECK = "trust-policy-validation"
GROUP = 'trust_policies'
SERVICES = ['iam']

ERR_MALFORMED_POLICY = "MalformedPolicyDocument"

VALID_TRUST_POLICY = json.dumps(
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRole with a valid trust policy succeeds, while one whose trust policy has no Statement
    raises MalformedPolicyDocument and the role is never persisted."""
    iam = ctx.client("iam")

    good_name = ctx.unique_name("sim2real-behav-role-ok-")
    iam.create_role(
        RoleName=good_name,
        AssumeRolePolicyDocument=VALID_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "trust-policy-validation"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_name))
    fetched = iam.get_role(RoleName=good_name)["Role"]
    assert fetched["RoleName"] == good_name, (
        f"positive control: expected role {good_name!r} to exist, got {fetched.get('RoleName')!r}"
    )

    bad_trust = json.dumps({"Version": "2012-10-17"})  # Missing Statement
    bad_name = ctx.unique_name("sim2real-behav-role-bad-")
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, bad_name))
    code, message = _error(
        lambda: iam.create_role(RoleName=bad_name, AssumeRolePolicyDocument=bad_trust)
    )
    assert code == ERR_MALFORMED_POLICY, f"Expected {ERR_MALFORMED_POLICY}, got {code!r}"
    expected = "Policy has no statements"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code2, message2 = _error(lambda: iam.get_role(RoleName=bad_name))
    assert code2 == "NoSuchEntity", f"role must not exist after a rejected create, got {code2!r}"
    expected2 = f"The role with name {bad_name} cannot be found."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {result!r}")


def _delete_role_if_exists(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
