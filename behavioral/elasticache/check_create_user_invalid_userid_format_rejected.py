"""create-user-invalid-userid-format-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-invalid-userid-format-rejected"
GROUP = "negative-classes"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUser with a UserId that starts with a digit, or that holds an underscore, is
    rejected with InvalidParameterValue and creates no user, while a UserId built from the
    same characters minus the violation is accepted."""
    ec = ctx.client("elasticache")

    valid_suffix = ctx.unique_name("ecu").replace("-", "")
    password = "Fidelity-Pr0bes-Pattern-9!"

    digit_leading_id = f"9{valid_suffix}"
    code, message = _error(
        lambda: ec.create_user(
            UserId=digit_leading_id,
            UserName=digit_leading_id,
            Engine="redis",
            AccessString="on ~* &* +@all",
            Passwords=[password],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == (
        "User id must begin with a letter; must contain only ASCII letters, digits, and "
        "hyphens; and must not end with a hyphen or contain two consecutive hyphens."
    ), f"unexpected message for a digit-leading UserId: {message!r}"

    # Effect absent: a digit-leading id was never created.
    not_found_code, not_found_message = _error(
        lambda: ec.describe_users(UserId=digit_leading_id)
    )
    assert not_found_code == "UserNotFound", f"expected UserNotFound, got {not_found_code!r}"
    assert not_found_message == f"User {digit_leading_id} not found.", not_found_message

    underscore_id = f"u_{valid_suffix}"
    code, message = _error(
        lambda: ec.create_user(
            UserId=underscore_id,
            UserName=underscore_id,
            Engine="redis",
            AccessString="on ~* &* +@all",
            Passwords=[password],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == (
        "User id must begin with a letter; must contain only ASCII letters, digits, and "
        "hyphens; and must not end with a hyphen or contain two consecutive hyphens."
    ), f"unexpected message for a UserId holding an underscore: {message!r}"

    not_found_code, not_found_message = _error(lambda: ec.describe_users(UserId=underscore_id))
    assert not_found_code == "UserNotFound", f"expected UserNotFound, got {not_found_code!r}"
    assert not_found_message == f"User {underscore_id} not found.", not_found_message

    # Positive control: the same characters, letter-led and hyphenated instead of
    # underscored, are a valid UserId and create a real user.
    valid_id = f"u-{valid_suffix}"
    ec.create_user(
        UserId=valid_id,
        UserName=valid_id,
        Engine="redis",
        AccessString="on ~* &* +@all",
        Passwords=[password],
    )
    ctx.on_cleanup(lambda: ec.delete_user(UserId=valid_id))
    created = ec.describe_users(UserId=valid_id)["Users"][0]
    assert created["UserId"] == valid_id, created
    assert created["Status"] in ("active", "modifying"), created["Status"]


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
