"""tag-role."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

MINIMAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

CHECK = "tag-role"
GROUP = 'tags'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagRole -> ListRoleTags returns exactly the tags just set; once the role is deleted,
    ListRoleTags on it is NoSuchEntity."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role: _delete_role_if_present(iam, n))
    iam.tag_role(
        RoleName=role,
        Tags=[
            {"Key": "env", "Value": "sim2real"},
            {"Key": "purpose", "Value": "behavioral-test"},
        ],
    )
    resp = iam.list_role_tags(RoleName=role)
    tag_map = {t["Key"]: t["Value"] for t in resp["Tags"]}
    assert tag_map == {"env": "sim2real", "purpose": "behavioral-test"}, (
        f"expected exactly the two tags just set, got {tag_map}"
    )
    assert resp["IsTruncated"] is False, f"expected IsTruncated False, got {resp['IsTruncated']}"

    iam.delete_role(RoleName=role)
    code, message = _error(lambda: iam.list_role_tags(RoleName=role))
    assert code == "NoSuchEntity", (
        f"expected NoSuchEntity for ListRoleTags on a deleted role, got {code}"
    )
    expected = f"The role with name {role} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _delete_role_if_present(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
