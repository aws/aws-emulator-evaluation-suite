"""op-contract-untag-user."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-untag-user"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagUser removes only the named keys, leaves siblings intact, and is a no-op for an absent
    key; a missing user is NoSuchEntity with the exact message."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.tag_user(UserName=user_name, Tags=[{"Key": "A", "Value": "1"}, {"Key": "B", "Value": "2"}])

    iam.untag_user(UserName=user_name, TagKeys=["A"])
    remaining = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user_name)["Tags"]}
    assert remaining == {"B": "2"}, remaining

    # Removing an already-absent key is idempotent, not an error.
    iam.untag_user(UserName=user_name, TagKeys=["A"])
    remaining2 = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user_name)["Tags"]}
    assert remaining2 == {"B": "2"}, remaining2

    # Error boundary: the target user does not exist.
    ghost = ctx.unique_name("sim2real-ghost-user-")
    code, message = _error(lambda: iam.untag_user(UserName=ghost, TagKeys=["A"]))
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The user with name {ghost} cannot be found."
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
