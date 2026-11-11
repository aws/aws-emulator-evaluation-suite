"""get-principal-tag-attribute-map-unknown-provider-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-principal-tag-attribute-map-unknown-provider-not-found"
GROUP = 'error-semantics'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPrincipalTagAttributeMap on a provider never associated with the pool is not-found,
    while the identical call for a provider that DOES have a configured map on this same pool
    succeeds — so a target that rejects every Get, not just this provider, cannot pass."""
    ev = ctx.client("cognito-identity")
    known_provider = "graph.facebook.com"
    pool_id = _create_pool(
        ev,
        ctx,
        allow_unauth=True,
        SupportedLoginProviders={known_provider: ctx.unique_name("app-")},
    )

    # Positive control: a provider that IS configured on the pool, given a configured
    # map, is readable — so a target that rejects every Get, not just this provider,
    # cannot pass.
    known_map = {"department": "sub"}
    ev.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id,
        IdentityProviderName=known_provider,
        UseDefaults=False,
        PrincipalTags=known_map,
    )
    live = ev.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=known_provider
    )
    assert live["PrincipalTags"] == known_map, (
        f"expected the configured map back for {known_provider!r}, got {live['PrincipalTags']!r}"
    )

    # The negative: a provider that was never associated with or configured on this pool.
    unknown_provider = f"cognito-idp.{ctx.region}.amazonaws.com/{ctx.region}_doesnotexist"
    code, message = _error(
        lambda: ev.get_principal_tag_attribute_map(
            IdentityPoolId=pool_id,
            IdentityProviderName=unknown_provider,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"No Principal Tags configured for Provider {unknown_provider}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
