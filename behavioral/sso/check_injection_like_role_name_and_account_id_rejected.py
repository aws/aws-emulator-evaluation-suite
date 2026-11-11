"""injection-like-role-name-and-account-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "injection-like-role-name-and-account-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso"]
MESSAGE = "Session token not found or invalid"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRoleCredentials with injection-shaped roleName and accountId strings is rejected with
    UnauthorizedException and the exact message, never a 5xx, another error or a success."""
    sso = ctx.client("sso")
    bogus_token = f"sim2real-bogus-{ctx.unique_name('tok')}"

    code, message = _error(
        lambda: sso.get_role_credentials(
            roleName="'; DROP TABLE roles; --",
            accountId="000000000000' OR '1'='1",
            accessToken=bogus_token,
        )
    )
    assert code == "UnauthorizedException", f"expected UnauthorizedException, got {code!r}"
    assert message == MESSAGE, f"expected {MESSAGE!r}, got {message!r}"


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
