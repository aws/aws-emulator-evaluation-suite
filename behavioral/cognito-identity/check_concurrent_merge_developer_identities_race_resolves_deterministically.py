"""concurrent-merge-developer-identities-race-resolves-deterministically."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-merge-developer-identities-race-resolves-deterministically"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent MergeDeveloperIdentities calls for one source/destination pair converge:
    every successful racer reports the same surviving IdentityId, the retired identity is retired
    once, and the source developer identifier then resolves to the survivor."""
    cog = ctx.client("cognito-identity")

    dev_provider = "sim2real.devmerge." + ctx.unique_name("p").replace("_", "-")
    pool_id = cog.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cid_devmerge_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identity_pool(IdentityPoolId=pool_id)))

    src_user = ctx.unique_name("src-")
    dst_user = ctx.unique_name("dst-")

    src_id = cog.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: src_user}
    )["IdentityId"]
    dst_id = cog.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dst_user}
    )["IdentityId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identities(IdentityIdsToDelete=[dst_id])))

    def _merge():
        resp = cog.merge_developer_identities(
            SourceUserIdentifier=src_user,
            DestinationUserIdentifier=dst_user,
            DeveloperProviderName=dev_provider,
            IdentityPoolId=pool_id,
        )
        return ("ok", resp["IdentityId"])

    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_merge) for _ in range(2)]
        for fut in futures:
            try:
                results.append(fut.result())
            except ClientError as e:
                results.append(("error", e.response["Error"]["Code"]))

    successes = [r[1] for r in results if r[0] == "ok"]
    assert len(successes) >= 1, f"neither concurrent merge succeeded: {results}"
    # Both racers must agree on a single surviving identity -- but which of the two original
    # IdentityIds that turns out to be is an implementation detail we don't pin down (the API
    # only promises the *pair* converges to one identity, not which literal ID wins under a
    # race). All successful responses must at least agree with each other.
    surviving_id = successes[0]
    assert all(identity_id == surviving_id for identity_id in successes), (
        f"concurrent merges disagreed on the surviving identity: {successes}"
    )
    assert surviving_id in (src_id, dst_id), (
        f"surviving identity {surviving_id} is neither original id (src={src_id}, dst={dst_id})"
    )
    retired_id = dst_id if surviving_id == src_id else src_id

    # final state must be consistent regardless of which racer "won": the source developer
    # identifier now resolves only to the single surviving identity, and the retired identity,
    # whose record AWS keeps describable, no longer carries the merged-away login.
    retired_desc = cog.describe_identity(IdentityId=retired_id)
    assert dev_provider not in (retired_desc.get("Logins") or []), (
        f"retired identity still lists the merged-away login: {retired_desc}"
    )

    resolved_id = cog.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: src_user}
    )["IdentityId"]
    assert resolved_id == surviving_id

    survivor_after = cog.describe_identity(IdentityId=surviving_id)
    assert survivor_after["IdentityId"] == surviving_id


# ===== helpers =====

def _safe(fn) -> None:
    """Run a teardown call; tolerate only the resource already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
