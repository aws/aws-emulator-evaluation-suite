"""get-id-rejects-unconfigured-login-provider."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-id-rejects-unconfigured-login-provider"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected success raises, so an
    over-permissive target never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be refused, but it SUCCEEDED and returned {result!r}"
    )


def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive guard: GetId with a login provider the pool never configured must be
    rejected -- distinct from a pool whose GetId simply rejects every call (positive control)
    and without silently minting an identity for the rejected login (effect absent)."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)

    # Positive control: the same pool mints a real identity for a plain unauthenticated request.
    control_identity = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert control_identity.startswith(f"{ctx.region}:"), (
        f"expected an identity id prefixed with the region, got {control_identity!r}"
    )
    before_ids = {
        i["IdentityId"]
        for i in ev.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]
    }
    assert control_identity in before_ids, (
        f"positive-control identity {control_identity!r} missing from ListIdentities {before_ids}"
    )

    code, message = _refusal(
        lambda: ev.get_id(
            IdentityPoolId=pool_id,
            Logins={"graph.facebook.com": "totally-bogus-provider-token"},
        )
    )
    assert code == "NotAuthorizedException", (
        f"pool has no SupportedLoginProviders entry for graph.facebook.com; "
        f"expected NotAuthorizedException, got {code!r}: {message!r}"
    )
    assert message == (f"Identity pool - {pool_id} does not have identity providers configured."), (
        message
    )

    # Effect absent: the rejected login minted no identity.
    after_ids = {
        i["IdentityId"]
        for i in ev.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]
    }
    assert after_ids == before_ids, (
        f"rejected login must not mint an identity; before={before_ids} after={after_ids}"
    )

    # Restore-style beat: the pool's normal (unauthenticated) path still works afterward.
    another_identity = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert another_identity.startswith(f"{ctx.region}:"), (
        f"expected an identity id prefixed with the region, got {another_identity!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
