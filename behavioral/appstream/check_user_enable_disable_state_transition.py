"""user-enable-disable-state-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "user-enable-disable-state-transition"
GROUP = "lifecycle"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUser starts Enabled=True; DisableUser/EnableUser flip Users[].Enabled, creating the
    same UserName+AuthenticationType twice is rejected, and once deleted the user is both invisible
    to DescribeUsers and unusable by a subsequent mutation."""
    appstream = ctx.client("appstream")

    user_name = f"{ctx.unique_name('sim2real-appstream-user-')}@example.com"
    auth_type = "USERPOOL"

    appstream.create_user(UserName=user_name, AuthenticationType=auth_type, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: _delete_if_present(appstream, user_name, auth_type))

    def _match() -> list:
        return [u for u in appstream.describe_users(AuthenticationType=auth_type)["Users"] if u["UserName"] == user_name]

    def _enabled() -> bool:
        # DescribeUsers can lag CreateUser/EnableUser/DisableUser briefly; bounded retry for that lag.
        deadline = time.monotonic() + 30
        matches: list = []
        while time.monotonic() < deadline:
            matches = _match()
            if len(matches) == 1:
                return matches[0]["Enabled"]
            time.sleep(2)
        raise AssertionError(f"user {user_name} never became visible via DescribeUsers: {matches}")

    def _gone() -> None:
        # DeleteUser's removal from DescribeUsers is likewise eventually consistent.
        deadline = time.monotonic() + 30
        matches: list = _match()
        while matches and time.monotonic() < deadline:
            time.sleep(2)
            matches = _match()
        if matches:
            raise AssertionError(f"user {user_name} still visible via DescribeUsers after delete: {matches}")

    enabled = _enabled()
    assert enabled is True, f"expected a freshly created user Enabled=True, got Enabled={enabled}"

    # duplicate create for the same UserName+AuthenticationType is rejected
    code, message = _error(
        lambda: appstream.create_user(UserName=user_name, AuthenticationType=auth_type, MessageAction="SUPPRESS")
    )
    assert code == "ResourceAlreadyExistsException", (
        f"expected a duplicate CreateUser for the same UserName+AuthenticationType to fail with "
        f"ResourceAlreadyExistsException, got {code!r}"
    )
    expected_message = "A user with that username already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    appstream.disable_user(UserName=user_name, AuthenticationType=auth_type)
    enabled = _enabled()
    assert enabled is False, f"expected DisableUser to flip Enabled to False, got Enabled={enabled}"

    appstream.enable_user(UserName=user_name, AuthenticationType=auth_type)
    enabled = _enabled()
    assert enabled is True, f"expected EnableUser to flip Enabled back to True, got Enabled={enabled}"

    appstream.delete_user(UserName=user_name, AuthenticationType=auth_type)
    _gone()

    # message varies: it embeds the per-request id of the underlying identity-provider call
    dead_code, _dead_message = _error(lambda: appstream.disable_user(UserName=user_name, AuthenticationType=auth_type))
    assert dead_code == "ResourceNotFoundException", (
        f"expected DisableUser against a deleted user to fail with ResourceNotFoundException, got {dead_code!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the botocore error it raises. An unexpected SUCCESS
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_if_present(appstream, user_name: str, auth_type: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appstream.delete_user(UserName=user_name, AuthenticationType=auth_type)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
