"""op-contract-untag-role."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-untag-role"
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
    """UntagRole removes only the named keys, leaves siblings intact, and is a no-op for an absent
    key; a missing role is NoSuchEntity with the exact message."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_DOC)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.tag_role(RoleName=role_name, Tags=[{"Key": "A", "Value": "1"}, {"Key": "B", "Value": "2"}])

    iam.untag_role(RoleName=role_name, TagKeys=["A"])
    remaining = {t["Key"]: t["Value"] for t in iam.list_role_tags(RoleName=role_name)["Tags"]}
    assert remaining == {"B": "2"}, f"expected only sibling tag B=2 to remain, got {remaining}"

    # Removing an already-absent key is idempotent, not an error.
    iam.untag_role(RoleName=role_name, TagKeys=["A"])
    remaining2 = {t["Key"]: t["Value"] for t in iam.list_role_tags(RoleName=role_name)["Tags"]}
    assert remaining2 == {"B": "2"}, f"expected re-removing absent key A to be a no-op, got {remaining2}"

    # Error boundary: the target role does not exist.
    ghost = ctx.unique_name("sim2real-ghost-role-")
    code, message = _error(lambda: iam.untag_role(RoleName=ghost, TagKeys=["A"]))
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The role with name {ghost} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
