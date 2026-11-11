"""merge-developer-identities-combines-logins."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "merge-developer-identities-combines-logins"
GROUP = 'developer-identity'
SERVICES = ['cognito-identity']

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """Create an identity pool with best-effort cleanup; return its id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"env": "test", "owner": "fidelity-check"},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MergeDeveloperIdentities collapses two developer identities into one: despite the naming,
    AWS keeps the SOURCE identity, so the response IdentityId is the source's, not the destination's."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True, DeveloperProviderName="login.myapp")
    source_user = ctx.unique_name("sim2real-behav-devuser-src-")
    dest_user = ctx.unique_name("sim2real-behav-devuser-dst-")
    # The destination identity is minted first, so a survivor chosen by age (the older identity)
    # cannot pass as "the source survives".
    dest_identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={"login.myapp": dest_user}
    )["IdentityId"]
    source_identity_id = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={"login.myapp": source_user}
    )["IdentityId"]
    assert source_identity_id != dest_identity_id, (
        f"two distinct developer users must mint two distinct identities, got {source_identity_id} twice"
    )
    merge_resp = ev.merge_developer_identities(
        SourceUserIdentifier=source_user,
        DestinationUserIdentifier=dest_user,
        DeveloperProviderName="login.myapp",
        IdentityPoolId=pool_id,
    )
    survivor = merge_resp["IdentityId"]
    assert survivor == source_identity_id, (
        f"merge must retain the source identity {source_identity_id}, got {survivor} "
        f"(destination was {dest_identity_id})"
    )
    for user in (source_user, dest_user):
        lookup = ev.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=user, MaxResults=10
        )
        assert lookup["IdentityId"] == survivor, (
            f"after merge, {user} must resolve to the surviving identity {survivor}, got {lookup['IdentityId']}"
        )
    identifiers = ev.lookup_developer_identity(
        IdentityPoolId=pool_id, IdentityId=survivor, MaxResults=10
    ).get("DeveloperUserIdentifierList", [])
    assert source_user in identifiers and dest_user in identifiers, (
        f"surviving identity must own both developer identifiers, got {identifiers}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
