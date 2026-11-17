"""update-group-new-path-malformed-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-group-new-path-malformed-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup rejects a NewPath lacking the required leading and trailing slash with
    ValidationError, leaving the group's path unchanged; a well-formed path is accepted."""
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-grp-newpath-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    original_path = iam.get_group(GroupName=group_name)["Group"]["Path"]
    assert original_path == "/", f"expected default Path '/', got {original_path!r}"

    bad_path = "not-a-path"
    code, message = _error(lambda: iam.update_group(GroupName=group_name, NewPath=bad_path))
    assert code == "ValidationError", f"expected ValidationError for a path with no slashes, got {code}"
    expected = (
        "The specified value for newPath is invalid. It must begin and end with / and contain "
        "only alphanumeric characters and/or / characters."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected update left the group's path unchanged.
    after = iam.get_group(GroupName=group_name)["Group"]["Path"]
    assert after == original_path, f"Path changed by a rejected UpdateGroup: {original_path!r} -> {after!r}"

    # Positive control: a well-formed path is accepted.
    good_path = "/sim2real-ok/"
    iam.update_group(GroupName=group_name, NewPath=good_path)
    accepted = iam.get_group(GroupName=group_name)["Group"]["Path"]
    assert accepted == good_path, f"expected Path {good_path!r} to be accepted, got {accepted!r}"


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a NewPath with no leading/trailing slash, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
