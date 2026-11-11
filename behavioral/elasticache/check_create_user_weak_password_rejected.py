"""create-user-weak-password-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-weak-password-rejected"
GROUP = "negative-classes"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUser with a password shorter than the ElastiCache-enforced minimum length
    (16 characters) is rejected with InvalidParameterValue rather than silently accepted."""
    ec = ctx.client("elasticache")

    weak_user_id = ctx.unique_name("sim2real-weakpw-")
    weak_password = "short12"  # 7 chars, well under the 16-char minimum

    code, message = _error(
        lambda: ec.create_user(
            UserId=weak_user_id,
            UserName=weak_user_id,
            Engine="redis",
            AccessString="on ~* &* +@all",
            Passwords=[weak_password],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "Passwords length must be between 16-128 characters.", message

    # Effect absent: no user was created under this ID.
    not_found_code, not_found_message = _error(lambda: ec.describe_users(UserId=weak_user_id))
    assert not_found_code == "UserNotFound", f"expected UserNotFound, got {not_found_code!r}"
    assert not_found_message == f"User {weak_user_id} not found.", not_found_message

    # Positive control: a strong (>=16 char) password is accepted.
    strong_user_id = ctx.unique_name("sim2real-strongpw-")
    strong_password = "Str0ng-Passw0rd-2024!"
    ec.create_user(
        UserId=strong_user_id,
        UserName=strong_user_id,
        Engine="redis",
        AccessString="on ~* &* +@all",
        Passwords=[strong_password],
    )
    ctx.on_cleanup(lambda: ec.delete_user(UserId=strong_user_id))
    created = ec.describe_users(UserId=strong_user_id)["Users"][0]
    assert created["UserId"] == strong_user_id, created
    assert created["Status"] in ("active", "modifying"), created["Status"]


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
