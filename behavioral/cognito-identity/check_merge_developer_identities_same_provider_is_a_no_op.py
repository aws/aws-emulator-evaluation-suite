"""merge-developer-identities-same-provider-is-a-no-op."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "merge-developer-identities-same-provider-is-a-no-op"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MergeDeveloperIdentities of two distinct identifiers returns the source identity, and a merge
    whose source and destination are the same identifier succeeds as a no-op that returns that
    identity and leaves it resolvable."""
    ci = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    user_src = ctx.unique_name("sim2real-user-src-")
    user_dst = ctx.unique_name("sim2real-user-dst-")
    id_src = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_src}
    )["IdentityId"]
    id_dst = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_dst}
    )["IdentityId"]
    assert id_src != id_dst, (
        f"distinct developer users must resolve to distinct identities, got {id_src!r} for both"
    )

    # A merge of two distinct developer users succeeds and keeps the SOURCE identity as the
    # survivor: the returned IdentityId is the source's, not the destination's.
    merge_resp = ci.merge_developer_identities(
        SourceUserIdentifier=user_src,
        DestinationUserIdentifier=user_dst,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    assert merge_resp["IdentityId"] == id_src, (
        f"positive-control merge should surface the surviving SOURCE identity "
        f"({id_src!r}), got {merge_resp['IdentityId']!r}"
    )

    # Self-merge is degenerate but well-formed: AWS accepts it as a no-op that returns the
    # identity's own IdentityId and leaves the identity resolvable.
    self_user = ctx.unique_name("sim2real-user-self-")
    self_id = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: self_user}
    )["IdentityId"]
    self_merge_resp = ci.merge_developer_identities(
        SourceUserIdentifier=self_user,
        DestinationUserIdentifier=self_user,
        DeveloperProviderName=dev_provider,
        IdentityPoolId=pool_id,
    )
    assert self_merge_resp["IdentityId"] == self_id, (
        f"self-merge no-op should return the identity's own IdentityId "
        f"({self_id!r}), got {self_merge_resp['IdentityId']!r}"
    )

    # The identity must still exist and be resolvable after the self-merge no-op.
    lookup = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, IdentityId=self_id, Logins={dev_provider: self_user}
    )
    assert lookup["IdentityId"] == self_id, (
        "self-merge no-op must not corrupt or remove the underlying identity"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
