"""op-contract-tag-user."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-tag-user"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagUser tags a user successfully, but rejects a call that supplies the same tag key twice."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.tag_user(UserName=user_name, Tags=[{"Key": "Team", "Value": "payments"}])
    tag_map = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user_name)["Tags"]}
    assert tag_map.get("Team") == "payments", tag_map

    # Rejection boundary: duplicate keys in the same TagUser call are invalid input, and must not
    # partially apply (the previously stored value survives untouched).
    code, message = _error(
        lambda: iam.tag_user(
            UserName=user_name, Tags=[{"Key": "Team", "Value": "a"}, {"Key": "Team", "Value": "b"}]
        )
    )
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "InvalidInput", f"expected InvalidInput, got {code}"
    expected = "Duplicate tag keys found. Please note that Tag keys are case insensitive."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    tag_map_after = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user_name)["Tags"]}
    assert tag_map_after.get("Team") == "payments", "rejected TagUser call must not mutate existing tags"


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
