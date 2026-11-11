"""e2e-unauthenticated-identity-access-disabled-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-unauthenticated-identity-access-disabled-rejected"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetId without Logins on a pool with AllowUnauthenticatedIdentities=False is refused with
    NotAuthorizedException and the exact message and creates no identity, while a pool that allows
    it issues one that ListIdentities shows."""
    cognito = ctx.client("cognito-identity")

    locked_pool_id = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cog_locked_"),
        AllowUnauthenticatedIdentities=False,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=locked_pool_id))

    open_pool_id = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cog_open_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=open_pool_id))

    err = _client_error(lambda: cognito.get_id(IdentityPoolId=locked_pool_id))
    assert err == ("NotAuthorizedException", "Unauthenticated access is not supported for this identity pool."), f"expected NotAuthorizedException, got {err!r}"

    # effect absent: the rejected GetId created no identity in the locked pool.
    listed = cognito.list_identities(IdentityPoolId=locked_pool_id, MaxResults=15)
    assert listed.get("Identities", []) == [], (
        f"expected no identities in the locked pool, got {listed.get('Identities')!r}"
    )

    # positive control: the sibling pool, identical except for the unauth flag, works fine.
    identity_id = cognito.get_id(IdentityPoolId=open_pool_id)["IdentityId"]
    assert identity_id, "expected GetId on the open pool to return an IdentityId"
    listed_open = cognito.list_identities(IdentityPoolId=open_pool_id, MaxResults=15)
    assert any(i["IdentityId"] == identity_id for i in listed_open.get("Identities", [])), (
        f"expected {identity_id!r} in the open pool's identities, got {listed_open.get('Identities')!r}"
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
