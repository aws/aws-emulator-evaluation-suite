"""op-contract-listUserTags-exact-set."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listUserTags-exact-set"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Success path returns exactly the tags the user was created with; a missing user yields NoSuchEntityException."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-batch09-user-")
    iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real-batch", "Value": "09"}, {"Key": "team", "Value": "iam-checks"}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    resp = iam.list_user_tags(UserName=user_name)
    tag_map = {t["Key"]: t["Value"] for t in resp["Tags"]}
    assert tag_map == {"sim2real-batch": "09", "team": "iam-checks"}, tag_map
    assert resp["IsTruncated"] is False, f"expected IsTruncated False, got {resp['IsTruncated']!r}"

    # Error boundary: UserName that does not exist.
    bogus_user = ctx.unique_name("sim2real-batch09-missing-user-")
    code, message = _error(lambda: iam.list_user_tags(UserName=bogus_user))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The user with name {bogus_user} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected NoSuchEntity, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
