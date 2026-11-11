"""get-role-policy-contract."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-role-policy-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRolePolicy: success-path document round-trip + NoSuchEntity boundary."""
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-grp-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-inline-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    assert resp["RoleName"] == role_name, f"expected RoleName {role_name!r}, got {resp['RoleName']!r}"
    assert resp["PolicyName"] == policy_name, f"expected PolicyName {policy_name!r}, got {resp['PolicyName']!r}"
    got_action = resp["PolicyDocument"]["Statement"][0]["Action"]
    assert got_action == "s3:ListBucket", f"expected Action s3:ListBucket, got {got_action!r}"

    code, message = _error(
        lambda: iam.get_role_policy(RoleName=role_name, PolicyName="does-not-exist")
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for missing inline policy, got {code}"
    expected = "The role policy with name does-not-exist cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, else raise."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
