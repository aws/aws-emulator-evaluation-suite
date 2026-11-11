"""op-contract-tag-role."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-tag-role"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagRole adds tags and overwrites an existing key's value in place (no duplicate keys)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_DOC)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.tag_role(RoleName=role_name, Tags=[{"Key": "Env", "Value": "test"}])
    tags1 = {t["Key"]: t["Value"] for t in iam.list_role_tags(RoleName=role_name)["Tags"]}
    assert tags1.get("Env") == "test", f"expected Env=test, got {tags1}"

    # Re-tagging the same key overwrites the value; it must not create a duplicate entry.
    iam.tag_role(RoleName=role_name, Tags=[{"Key": "Env", "Value": "prod"}])
    tags2 = iam.list_role_tags(RoleName=role_name)["Tags"]
    env_entries = [t for t in tags2 if t["Key"] == "Env"]
    assert len(env_entries) == 1, f"expected exactly one Env tag, got {env_entries}"
    assert env_entries[0]["Value"] == "prod", f"expected Env=prod, got {env_entries[0]!r}"

    # Error boundary: the target role does not exist.
    ghost = ctx.unique_name("sim2real-ghost-role-")
    code, message = _error(
        lambda: iam.tag_role(RoleName=ghost, Tags=[{"Key": "Env", "Value": "test"}])
    )
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The role with name {ghost} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
