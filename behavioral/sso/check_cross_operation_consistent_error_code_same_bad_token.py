"""cross-operation-consistent-error-code-same-bad-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-operation-consistent-error-code-same-bad-token"
GROUP = "error-semantics"
SERVICES = ["sso"]
MESSAGE = "Session token not found or invalid"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The same invalid bearer token is rejected with UnauthorizedException and the same exact message by
    GetRoleCredentials, ListAccountRoles, ListAccounts and Logout."""
    sso = ctx.client("sso")
    bogus_token = f"sim2real-bogus-{ctx.unique_name('tok')}"

    calls = {
        "GetRoleCredentials": lambda: sso.get_role_credentials(
            roleName="AdministratorAccess", accountId="111122223333", accessToken=bogus_token
        ),
        "ListAccountRoles": lambda: sso.list_account_roles(
            accessToken=bogus_token, accountId="111122223333"
        ),
        "ListAccounts": lambda: sso.list_accounts(accessToken=bogus_token),
        "Logout": lambda: sso.logout(accessToken=bogus_token),
    }

    errors = {name: _error(name, fn) for name, fn in calls.items()}
    for name, (code, message) in errors.items():
        assert code == "UnauthorizedException", (
            f"{name}: expected UnauthorizedException, got {code!r} (errors={errors})"
        )
        assert message == MESSAGE, f"{name}: expected {MESSAGE!r}, got {message!r}"


def _error(name, fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"{name}: real AWS rejects this call with a bogus bearer token, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
