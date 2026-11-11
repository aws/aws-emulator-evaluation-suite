"""lookup-developer-identity-cross-pool-isolation."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lookup-developer-identity-cross-pool-isolation"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the ClientError (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK}, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """LookupDeveloperIdentity MUST NOT resolve an identity that belongs to a DIFFERENT identity
    pool -- pools are isolated tenants -- while the same lookup against the owning pool succeeds."""
    ev = ctx.client("cognito-identity")
    provider_a = ctx.unique_name("dev-provider-a-")
    provider_b = ctx.unique_name("dev-provider-b-")
    pool_a = _create_pool(ev, ctx, allow_unauth=False, DeveloperProviderName=provider_a)
    pool_b = _create_pool(ev, ctx, allow_unauth=False, DeveloperProviderName=provider_b)
    user_id = ctx.unique_name("iso-user-")

    identity_a = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_a, Logins={provider_a: user_id}
    )["IdentityId"]

    code, message = _error(
        lambda: ev.lookup_developer_identity(
            IdentityPoolId=pool_b, IdentityId=identity_a, MaxResults=10
        )
    )
    assert code == "NotAuthorizedException", (
        f"expected cross-pool lookup of {identity_a} to be rejected with "
        f"NotAuthorizedException, got {code}"
    )
    expected = "You do not have access to this identity"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Sanity: the very same lookup against the OWNING pool succeeds, proving the
    # rejection above is genuine tenant isolation and not a blanket failure.
    same_pool = ev.lookup_developer_identity(
        IdentityPoolId=pool_a, IdentityId=identity_a, MaxResults=10
    )
    assert same_pool["IdentityId"] == identity_a, (
        f"expected the owning pool's lookup of {identity_a} to resolve to itself, got "
        f"{same_pool['IdentityId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
