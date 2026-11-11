"""op-contract-listEntitiesForPolicy-role-and-user."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listEntitiesForPolicy-role-and-user"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
)
_POLICY_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}]}
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEntitiesForPolicy lists exactly the attached role and user and no groups; a well-formed
    but unknown PolicyArn is rejected with NoSuchEntity and the exact message.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListEntitiesForPolicy.html
    """
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-batch09-policy-")
    policy_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=_POLICY_DOC,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    role_name = ctx.unique_name("sim2real-batch09-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    user_name = ctx.unique_name("sim2real-batch09-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn))

    resp = iam.list_entities_for_policy(PolicyArn=policy_arn)
    role_names = {r["RoleName"] for r in resp["PolicyRoles"]}
    user_names = {u["UserName"] for u in resp["PolicyUsers"]}
    assert role_names == {role_name}, f"expected only {role_name}, got {role_names}"
    assert user_names == {user_name}, f"expected only {user_name}, got {user_names}"
    assert resp["PolicyGroups"] == [], f"expected no attached groups, got {resp['PolicyGroups']}"

    bogus_arn = policy_arn.rsplit("/", 1)[0] + "/does-not-exist-" + ctx.unique_name("")
    code, message = _error(lambda: iam.list_entities_for_policy(PolicyArn=bogus_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"Policy {bogus_arn} does not exist or is not attachable."
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
