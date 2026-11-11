"""op-contract-create-role."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-create-role"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRole: success-path returns a Role whose AssumeRolePolicyDocument round-trips
    the supplied trust policy; error boundary is MalformedPolicyDocumentException for a
    syntactically invalid trust document, and that rejection must leave no role behind."""
    iam = ctx.client("iam")
    tag_set = [{"Key": "sim2real", "Value": CHECK}]

    role_name = ctx.unique_name("sim2real-role-")
    created = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY, Tags=tag_set
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    assert created["RoleName"] == role_name, f"expected RoleName {role_name!r}, got {created['RoleName']!r}"
    assert created["Arn"].endswith(f":role/{role_name}"), (
        f"expected Arn ending in :role/{role_name}, got {created['Arn']!r}"
    )
    trust_doc = created["AssumeRolePolicyDocument"]
    statement = trust_doc["Statement"][0]
    assert statement["Principal"]["Service"] == "ec2.amazonaws.com", (
        f"expected trust doc Principal.Service ec2.amazonaws.com, got {statement['Principal']!r}"
    )
    assert statement["Action"] == "sts:AssumeRole", (
        f"expected trust doc Action sts:AssumeRole, got {statement['Action']!r}"
    )

    fetched = iam.get_role(RoleName=role_name)["Role"]
    assert fetched["RoleId"] == created["RoleId"], (
        f"independent GetRole RoleId {fetched['RoleId']!r} != CreateRole RoleId {created['RoleId']!r}"
    )

    bad_role_name = ctx.unique_name("sim2real-bad-role-")
    ctx.on_cleanup(lambda: _delete_if_present(iam, bad_role_name))
    code, message = _error(
        lambda: iam.create_role(
            RoleName=bad_role_name,
            AssumeRolePolicyDocument="{not valid json",
            Tags=tag_set,
        )
    )
    assert code == "MalformedPolicyDocument", f"expected MalformedPolicyDocument, got {code}"
    expected = "This policy contains invalid Json"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    absent_code, absent_message = _error(lambda: iam.get_role(RoleName=bad_role_name))
    assert absent_code == "NoSuchEntity", (
        f"a rejected CreateRole must not create the role: expected GetRole NoSuchEntity, got {absent_code}"
    )
    expected = f"The role with name {bad_role_name} cannot be found."
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_if_present(iam, role_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
