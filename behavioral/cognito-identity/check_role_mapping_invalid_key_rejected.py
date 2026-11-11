"""role-mapping-invalid-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-mapping-invalid-key-rejected"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles with a Roles key other than authenticated or unauthenticated is refused
    with ValidationException and the exact message and stores nothing, while a valid Roles map on
    the same pool is stored."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    bogus_role_arn = f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:role/sim2real-bogus-role"
    code, message = _error(
        lambda: ci.set_identity_pool_roles(
            IdentityPoolId=pool_id,
            Roles={"superadmin": bogus_role_arn},  # only "authenticated"/"unauthenticated" allowed
        )
    )
    assert code == "ValidationException", f"unexpected error code: {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{{superadmin={bogus_role_arn}}}' at 'roles' "
        "failed to satisfy constraint: Map keys must satisfy constraint: "
        "[Member must have length less than or equal to 128, "
        "Member must have length greater than or equal to 1, "
        "Member must satisfy regular expression pattern: (un)?authenticated]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


    # Effect absent: GetIdentityPoolRoles on the fresh pool succeeds with no Roles, so the
    # rejected "superadmin" key was never persisted.
    unset_roles = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert not unset_roles.get("Roles"), (
        f"expected no roles to have been persisted by the rejected call, got "
        f"{unset_roles.get('Roles')!r}"
    )


    # Positive control: a valid Roles map on the same pool is accepted and persisted.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    auth_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-auth-role"
    unauth_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-unauth-role"

    valid_roles = {"authenticated": auth_role_arn, "unauthenticated": unauth_role_arn}
    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=valid_roles)
    got = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert got["Roles"] == valid_roles, (
        f"expected the valid Roles map to round-trip as {valid_roles!r}, got {got['Roles']!r}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
