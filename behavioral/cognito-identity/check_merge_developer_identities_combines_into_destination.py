"""merge-developer-identities-combines-into-destination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "merge-developer-identities-combines-into-destination"
GROUP = "state"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MergeDeveloperIdentities returns the source identity as the surviving IdentityId, and
    LookupDeveloperIdentity for both the source and the destination user identifier then resolves to
    it."""
    ci = ctx.client("cognito-identity")
    dev_provider = "login.sim2real.devmerge"
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real-check": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    src_user = ctx.unique_name("user-merge-src-")
    dst_user = ctx.unique_name("user-merge-dst-")
    src_identity = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: src_user}
    )["IdentityId"]
    dst_identity = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dst_user}
    )["IdentityId"]
    assert src_identity != dst_identity, (
        f"two distinct developer logins should mint two distinct identities, got {src_identity} twice"
    )

    merge_resp = ci.merge_developer_identities(
        SourceUserIdentifier=src_user,
        DestinationUserIdentifier=dst_user,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    assert merge_resp["IdentityId"] == src_identity, (
        f"merge result {merge_resp['IdentityId']} should equal the surviving source identity {src_identity}"
    )

    lookup_src = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=src_user, MaxResults=1
    )
    assert lookup_src["IdentityId"] == src_identity, (
        f"source developer user identifier should still resolve to {src_identity}, got {lookup_src['IdentityId']}"
    )
    lookup_dst = ci.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=dst_user, MaxResults=1
    )
    assert lookup_dst["IdentityId"] == src_identity, (
        "destination developer user identifier should now resolve to the surviving source identity"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

