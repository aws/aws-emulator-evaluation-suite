"""op-contract-getGroup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getGroup"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroup returns exactly the membership set after AddUserToGroup; a
    nonexistent group name is rejected with NoSuchEntityException."""
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-iam-ggrp-")
    user_name = ctx.unique_name("sim2real-iam-gguser-")
    # IAM groups have no Tags param on CreateGroup and no TagGroup API at all; the user is
    # taggable and is tagged below.
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    iam.add_user_to_group(GroupName=group_name, UserName=user_name)
    ctx.on_cleanup(lambda: iam.remove_user_from_group(GroupName=group_name, UserName=user_name))

    resp = iam.get_group(GroupName=group_name)
    assert resp["Group"]["GroupName"] == group_name, resp["Group"]
    user_names = [u["UserName"] for u in resp["Users"]]
    assert user_names == [user_name], user_names

    # IAM's wire-level Code for this shape is "NoSuchEntity" (the modeled exception
    # class name "NoSuchEntityException" is not the on-the-wire Code).
    missing = ctx.unique_name("sim2real-nope-")
    code, message = _error(lambda: iam.get_group(GroupName=missing))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code!r}"
    expected = f"The group with name {missing} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, else raise."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
