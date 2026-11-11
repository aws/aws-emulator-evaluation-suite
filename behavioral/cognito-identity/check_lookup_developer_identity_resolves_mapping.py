"""lookup-developer-identity-resolves-mapping."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "lookup-developer-identity-resolves-mapping"
GROUP = 'developer-identity'
SERVICES = ['cognito-identity']

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

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupDeveloperIdentity resolves IdentityId <-> DeveloperUserIdentifier both ways."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True, DeveloperProviderName="login.myapp")
    user_id = ctx.unique_name("sim2real-behav-devuser-")
    identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={"login.myapp": user_id}
    )["IdentityId"]
    by_identity = ev.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=identity_id, MaxResults=10
    )
    assert by_identity["IdentityId"] == identity_id, (
        f"expected lookup-by-identity to echo IdentityId {identity_id!r}, "
        f"got {by_identity.get('IdentityId')!r}"
    )
    assert user_id in by_identity.get("DeveloperUserIdentifierList", []), (
        f"expected {user_id!r} in DeveloperUserIdentifierList, "
        f"got {by_identity.get('DeveloperUserIdentifierList')!r}"
    )
    by_user = ev.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=user_id, MaxResults=10
    )
    assert by_user["IdentityId"] == identity_id, (
        f"expected lookup-by-developer-user-identifier to resolve to IdentityId {identity_id!r}, "
        f"got {by_user.get('IdentityId')!r}"
    )
    assert user_id in by_user.get("DeveloperUserIdentifierList", []), (
        f"expected {user_id!r} in DeveloperUserIdentifierList, "
        f"got {by_user.get('DeveloperUserIdentifierList')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
