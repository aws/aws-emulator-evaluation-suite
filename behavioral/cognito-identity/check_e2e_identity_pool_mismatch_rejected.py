"""e2e-identity-pool-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-identity-pool-mismatch-rejected"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A developer identity minted under Pool A cannot be addressed through Pool B (cross-tenant
    isolation): the identity is left unaffected by the rejected cross-pool call, and the same
    call against the correct pool succeeds (positive control in this file)."""
    cognito = ctx.client("cognito-identity")

    dp_a = ctx.unique_name("sim2real-behav-dpa-")
    dp_b = ctx.unique_name("sim2real-behav-dpb-")
    pool_a = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-poolA-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dp_a,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_a))
    pool_b = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-poolB-"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dp_b,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_b))

    user_id = ctx.unique_name("dev-user-")
    identity_id = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_a, Logins={dp_a: user_id}
    )["IdentityId"]

    err = _client_error(
        lambda: cognito.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_b, IdentityId=identity_id, Logins={dp_b: user_id}
        )
    )
    # An IdentityId belonging to a foreign identity pool is rejected with
    # NotAuthorizedException, not ResourceNotFoundException/ResourceConflictException -- ownership
    # is checked before the identity is looked up within pool B's scope.
    assert err == ("NotAuthorizedException", f"Access to Identity '{identity_id}' is forbidden."), f"expected NotAuthorizedException, got {err!r}"

    # Effect absent: the identity is unaffected -- it still only carries its pool-A login.
    logins = cognito.describe_identity(IdentityId=identity_id).get("Logins", [])
    assert dp_a in logins, f"expected {dp_a!r} in {logins!r}"
    assert dp_b not in logins, f"rejected cross-pool call nonetheless linked {dp_b!r}: {logins!r}"

    # Positive control: the same call against the correct pool succeeds.
    ok_resp = cognito.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_a, IdentityId=identity_id, Logins={dp_a: user_id}
    )
    assert ok_resp["IdentityId"] == identity_id, (
        f"expected {identity_id!r}, got {ok_resp['IdentityId']!r}"
    )


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
