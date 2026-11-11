"""unicode-role-name-query-param-rejected-safely."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unicode-role-name-query-param-rejected-safely"
GROUP = "overly-permissive"
SERVICES = ["sso"]
MESSAGE = "Session token not found or invalid"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRoleCredentials with an invalid token is rejected with UnauthorizedException and the same exact
    message whether roleName is plain ASCII or a multi-byte UTF-8 string: the encoded query parameter
    does not change the rejection path."""
    sso = ctx.client("sso")
    bogus_token = f"sim2real-bogus-{ctx.unique_name('tok')}"

    ascii_code, ascii_message = _error(
        lambda: sso.get_role_credentials(
            roleName="AdministratorAccess",
            accountId="111122223333",
            accessToken=bogus_token,
        )
    )
    assert ascii_code == "UnauthorizedException", (
        f"ASCII control: expected UnauthorizedException, got {ascii_code!r}"
    )
    assert ascii_message == MESSAGE, (
        f"ASCII control: expected {MESSAGE!r}, got {ascii_message!r}"
    )

    unicode_code, unicode_message = _error(
        lambda: sso.get_role_credentials(
            roleName="管理者Role🚀",
            accountId="111122223333",
            accessToken=bogus_token,
        )
    )
    assert unicode_code == "UnauthorizedException", (
        f"expected UnauthorizedException, got {unicode_code!r}"
    )
    assert unicode_message == MESSAGE, f"expected {MESSAGE!r}, got {unicode_message!r}"
    assert unicode_code == ascii_code, (
        f"Unicode roleName changed the error code: ascii={ascii_code!r} "
        f"unicode={unicode_code!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this bogus bearer token, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
