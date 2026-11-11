"""login-profile-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "login-profile-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A login profile progresses create->active->password-updated->deleted->404-on-get; the dead
    id also rejects a mutation, and the identifier is reusable once it is gone."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-loginprofile-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    password1 = "Sim2Real!Passw0rd-Alpha1"
    iam.create_login_profile(UserName=user_name, Password=password1, PasswordResetRequired=False)
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(lambda: iam.delete_login_profile(UserName=user_name))
    )

    profile = iam.get_login_profile(UserName=user_name)["LoginProfile"]
    assert profile["UserName"] == user_name, f"expected UserName {user_name!r}, got {profile!r}"
    assert profile.get("PasswordResetRequired", False) is False, (
        f"expected a freshly created profile to not require a reset, got {profile!r}"
    )

    password2 = "Sim2Real!Passw0rd-Beta2"
    _retry_unmodifiable(
        lambda: iam.update_login_profile(
            UserName=user_name, Password=password2, PasswordResetRequired=True
        )
    )

    profile = iam.get_login_profile(UserName=user_name)["LoginProfile"]
    assert profile["PasswordResetRequired"] is True, (
        f"expected UpdateLoginProfile to have set PasswordResetRequired, got {profile!r}"
    )

    _retry_unmodifiable(lambda: iam.delete_login_profile(UserName=user_name))

    expected_missing = f"Login Profile for User {user_name} cannot be found."
    code_get, message_get = _error_code(lambda: iam.get_login_profile(UserName=user_name))
    assert code_get == "NoSuchEntity", f"expected NoSuchEntity after delete, got {code_get!r}"
    assert message_get == expected_missing, (
        f"GetLoginProfile after delete must carry AWS's exact message {expected_missing!r}; "
        f"got {message_get!r}"
    )

    # a mutation on the now-dead login profile must fail the same way, not silently recreate it
    code_update, message_update = _error_code(
        lambda: iam.update_login_profile(UserName=user_name, PasswordResetRequired=True)
    )
    assert code_update == "NoSuchEntity", (
        f"expected UpdateLoginProfile on a deleted profile to fail NoSuchEntity, got {code_update!r}"
    )
    assert message_update == expected_missing, (
        f"UpdateLoginProfile on the deleted profile must carry AWS's exact message "
        f"{expected_missing!r}; got {message_update!r}"
    )

    # the identifier is reusable: the same user name can get a fresh login profile
    password3 = "Sim2Real!Passw0rd-Gamma3"
    _retry_unmodifiable(lambda: iam.create_login_profile(UserName=user_name, Password=password3))
    reused = iam.get_login_profile(UserName=user_name)["LoginProfile"]
    assert reused["UserName"] == user_name, (
        f"expected the recreated login profile to belong to {user_name!r}, got {reused!r}"
    )


def _error_code(fn, tries=6, delay=2.0):
    from botocore.exceptions import ClientError

    last_transient = None
    for _ in range(tries):
        try:
            fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityTemporarilyUnmodifiable":
                last_transient = exc
                time.sleep(delay)
                continue
            return code, exc.response["Error"].get("Message")
        else:
            raise AssertionError("expected the call to fail, but it succeeded")
    raise AssertionError(f"operation stayed temporarily unmodifiable after retries: {last_transient}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_unmodifiable(fn, tries=6, delay=2.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(tries):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityTemporarilyUnmodifiable":
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    raise AssertionError(f"operation stayed temporarily unmodifiable after retries: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
