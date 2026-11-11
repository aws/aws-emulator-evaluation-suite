"""concurrent-merge-developer-identities-same-source-serializes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-merge-developer-identities-same-source-serializes"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent MergeDeveloperIdentities calls merging one source into two destinations
    serialize: each succeeds or fails with a documented conflict error, at least one merges,
    and the source resolves to exactly one identity, stably."""
    cid = ctx.client("cognito-identity")
    dev_provider = ctx.unique_name("sim2real-dev-")
    pool = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))

    src_user = ctx.unique_name("sim2real-src-")
    dest_a_user = ctx.unique_name("sim2real-desta-")
    dest_b_user = ctx.unique_name("sim2real-destb-")

    src_id = cid.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: src_user}
    )["IdentityId"]
    dest_a_id = cid.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dest_a_user}
    )["IdentityId"]
    dest_b_id = cid.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dest_b_user}
    )["IdentityId"]
    ctx.on_cleanup(
        lambda: cid.delete_identities(IdentityIdsToDelete=[src_id, dest_a_id, dest_b_id])
    )

    def merge(dest_user):
        return cid.merge_developer_identities(
            SourceUserIdentifier=src_user,
            DestinationUserIdentifier=dest_user,
            DeveloperProviderName=dev_provider,
            IdentityPoolId=pool_id,
        )

    outcomes = {}
    with ThreadPoolExecutor(max_workers=2) as pool_exec:
        futures = {
            "A": pool_exec.submit(merge, dest_a_user),
            "B": pool_exec.submit(merge, dest_b_user),
        }
        for label, fut in futures.items():
            try:
                outcomes[label] = ("ok", fut.result())
            except ClientError as exc:
                outcomes[label] = ("error", exc.response["Error"]["Code"])

    # At least one of the two concurrent calls must actually perform the merge -- a target that
    # rejects every concurrent MergeDeveloperIdentities call with a plausible-sounding error would
    # otherwise pass this check by doing nothing at all, which is exactly the race this check
    # exists to exercise.
    successful_labels = [label for label, (kind, _) in outcomes.items() if kind == "ok"]
    assert successful_labels, f"neither concurrent merge call succeeded: {outcomes}"

    # Each concurrent call either succeeds outright or is rejected with a documented
    # conflict/authorization error -- an unexpected error code (e.g. InternalErrorException)
    # would indicate the server mishandled the race rather than serializing it.
    allowed_error_codes = {
        "ResourceConflictException",
        "NotAuthorizedException",
        "ResourceNotFoundException",
        "InvalidParameterException",
    }
    for label, (kind, val) in outcomes.items():
        if kind == "error":
            assert val in allowed_error_codes, f"unexpected error code for merge {label}: {val}"

    # The real property under test: regardless of how each individual call was resolved by the
    # race, the source settles on exactly one destination -- not both, and not neither.
    final = cid.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=src_user, MaxResults=10
    )
    final_id = final["IdentityId"]
    # The surviving IdentityId after a merge can be the source's own or a destination's, so any
    # of the three pre-merge identities is accepted; the property is that the lookup converges
    # on a single, stable winner.
    assert final_id in (src_id, dest_a_id, dest_b_id), (
        f"source resolved to an identity ({final_id}) that is none of the pre-merge identities "
        f"(src={src_id}, a={dest_a_id}, b={dest_b_id}): {outcomes}"
    )

    # The merge took effect: the surviving identity carries the source user and at least one
    # destination user (a no-op merge leaves the source identity holding only its own user).
    linked = cid.lookup_developer_identity(IdentityPoolId=pool_id, IdentityId=final_id, MaxResults=10)[
        "DeveloperUserIdentifierList"
    ]
    assert src_user in linked and {dest_a_user, dest_b_user} & set(linked), (
        f"surviving identity {final_id} links {linked!r}; expected {src_user!r} plus a destination user: {outcomes}"
    )

    # stability: resolution is not split-brain -- a second lookup shortly after agrees.
    final2 = cid.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=src_user, MaxResults=10
    )
    assert final2["IdentityId"] == final_id, (
        f"source identity resolution is not stable across repeated lookups: {final_id} vs {final2['IdentityId']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
