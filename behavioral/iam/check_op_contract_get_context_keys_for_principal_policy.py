"""op-contract-getContextKeysForPrincipalPolicy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-getContextKeysForPrincipalPolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetContextKeysForPrincipalPolicy returns exactly the key the principal's
    inline policy references (aws:PrincipalTag/Team), and a nonexistent
    PolicySourceArn fails with NoSuchEntity and its exact message."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-gckpp-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalTag/Team": "payments"}},
        },
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-inline"))

    resp = iam.get_context_keys_for_principal_policy(PolicySourceArn=role["Arn"])
    keys = set(resp["ContextKeyNames"])
    assert keys == {"aws:PrincipalTag/Team"}, f"expected exactly the referenced context key, got {keys}"

    bogus_arn = role["Arn"] + "-does-not-exist"
    code, message = _error(lambda: iam.get_context_keys_for_principal_policy(PolicySourceArn=bogus_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code!r}"
    expected = "Unable to retrieve specified IAM entity."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
