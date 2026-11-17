"""tag-user-fifty-tag-cap-overwrite-does-not-consume-it."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-user-fifty-tag-cap-overwrite-does-not-consume-it"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A user holds at most 50 tags; re-tagging an existing key to a new value never counts
    against that cap, and the 51st distinct key is refused while the 50 already set survive."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-tagcap-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    first_49 = [{"Key": f"sim2real-k{i}", "Value": "v0"} for i in range(49)]
    iam.tag_user(UserName=user_name, Tags=first_49)

    listed = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user_name)["Tags"]}
    assert len(listed) == 49, f"expected 49 tags after the first batch, got {len(listed)}"

    # positive control: re-tagging an existing key overwrites its value without growing the count.
    iam.tag_user(UserName=user_name, Tags=[{"Key": "sim2real-k0", "Value": "v1"}])
    listed = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user_name)["Tags"]}
    assert len(listed) == 49, f"expected the overwrite to leave the count at 49, got {len(listed)}"
    assert listed["sim2real-k0"] == "v1", f"expected sim2real-k0 overwritten to 'v1', got {listed['sim2real-k0']!r}"

    # the 50th distinct key reaches the cap exactly.
    iam.tag_user(UserName=user_name, Tags=[{"Key": "sim2real-k49", "Value": "v0"}])
    listed = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user_name)["Tags"]}
    assert len(listed) == 50, f"expected exactly 50 tags at the cap, got {len(listed)}"

    # a 51st distinct key is refused, and the 50 already set are left exactly as they were.
    code, message = _error(
        lambda: iam.tag_user(UserName=user_name, Tags=[{"Key": "sim2real-k50", "Value": "v0"}])
    )
    assert code == "LimitExceeded", f"expected LimitExceeded tagging a 51st key, got {code!r}"
    expected_message = "The number of tags has reached the maximum limit."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listed_after = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user_name)["Tags"]}
    assert len(listed_after) == 50, f"expected the refused call to leave 50 tags in place, got {len(listed_after)}"
    assert "sim2real-k50" not in listed_after, "the refused 51st key must not appear on the user"
    assert listed_after["sim2real-k0"] == "v1", (
        f"expected the earlier overwrite of sim2real-k0 to survive the refused call, got {listed_after['sim2real-k0']!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
