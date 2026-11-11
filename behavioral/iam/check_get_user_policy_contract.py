"""get-user-policy-contract."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-user-policy-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUserPolicy: success-path document round-trip + NoSuchEntity boundary."""
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-gup-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = "sim2real-inline-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    resp = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
    assert resp["UserName"] == user_name, f"expected UserName {user_name!r}, got {resp['UserName']!r}"
    assert resp["PolicyName"] == policy_name, (
        f"expected PolicyName {policy_name!r}, got {resp['PolicyName']!r}"
    )
    assert resp["PolicyDocument"]["Statement"][0]["Action"] == "s3:GetObject", (
        f"expected Action s3:GetObject, got {resp['PolicyDocument']['Statement'][0]['Action']!r}"
    )

    missing = "does-not-exist"
    code, message = _error(lambda: iam.get_user_policy(UserName=user_name, PolicyName=missing))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for missing inline policy, got {code}: {message!r}"
    expected = f"The user policy with name {missing} cannot be found."
    assert message == expected, f"NoSuchEntity message: expected {expected!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
