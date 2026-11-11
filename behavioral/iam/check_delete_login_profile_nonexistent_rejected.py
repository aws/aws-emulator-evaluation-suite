"""delete-login-profile-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-login-profile-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLoginProfile and GetLoginProfile on a user without a login profile fail with
    NoSuchEntity and the exact message; after a profile is created and deleted,
    UpdateLoginProfile and GetLoginProfile fail the same way."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-nologin-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    ctx.on_cleanup(lambda: _safe_delete_login_profile(iam, user_name))

    expected = f"Login Profile for User {user_name} cannot be found."
    code, message = _error(lambda: iam.delete_login_profile(UserName=user_name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code_get, message_get = _error(lambda: iam.get_login_profile(UserName=user_name))
    assert code_get == "NoSuchEntity", "user should still have no login profile"
    assert message_get == expected, f"expected message {expected!r}, got {message_get!r}"

    # positive control: create one, then the identical delete succeeds.
    iam.create_login_profile(UserName=user_name, Password="Sim2Real-Behav-2024!Pw2")
    iam.get_login_profile(UserName=user_name)  # now exists
    iam.delete_login_profile(UserName=user_name)

    # gone and unusable: a mutation against the now-deleted profile fails the same way a read does.
    code_update, message_update = _error(
        lambda: iam.update_login_profile(UserName=user_name, Password="Sim2Real-Behav-2024!Pw3")
    )
    assert code_update == "NoSuchEntity", f"expected NoSuchEntity on update, got {code_update}"
    assert message_update == expected, f"expected message {expected!r}, got {message_update!r}"

    code_after, message_after = _error(lambda: iam.get_login_profile(UserName=user_name))
    assert code_after == "NoSuchEntity", f"expected NoSuchEntity after delete, got {code_after}"
    assert message_after == expected, f"expected message {expected!r}, got {message_after!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_delete_login_profile(iam, user_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_login_profile(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
