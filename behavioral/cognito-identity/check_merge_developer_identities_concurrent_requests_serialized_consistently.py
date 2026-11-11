"""merge-developer-identities-concurrent-requests-serialized-consistently."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-developer-identities-concurrent-requests-serialized-consistently"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent MergeDeveloperIdentities calls for the same pair are serialized: both succeed
    and agree on one surviving IdentityId, and the final state links both developer identifiers to
    the survivor exactly once."""
    ci = ctx.client("cognito-identity")

    dev_provider_name = ctx.unique_name("sim2real-behav-dev-")
    pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider_name,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    dst_user = ctx.unique_name("sim2real-behav-dst-")
    src_user = ctx.unique_name("sim2real-behav-src-")

    ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider_name: dst_user}
    )["IdentityId"]
    ci.get_open_id_token_for_developer_identity(IdentityPoolId=pool_id, Logins={dev_provider_name: src_user})

    def _merge():
        try:
            resp = ci.merge_developer_identities(
                SourceUserIdentifier=src_user,
                DestinationUserIdentifier=dst_user,
                DeveloperProviderName=dev_provider_name,
                IdentityPoolId=pool_id,
            )
            return ("ok", resp["IdentityId"])
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool_executor:
        future_a = pool_executor.submit(_merge)
        future_b = pool_executor.submit(_merge)
        result_a = future_a.result(timeout=60)
        result_b = future_b.result(timeout=60)

    results = [result_a, result_b]
    # A merge of an already-merged pair is idempotent, so the losing call succeeds too. The
    # response IdentityId is the surviving identity, which may be either side's pre-merge id, so
    # only require that both calls agree on the same one.
    assert [r[0] for r in results] == ["ok", "ok"], f"expected both concurrent merge calls to succeed: {results!r}"
    surviving_id = result_a[1]
    assert result_b[1] == surviving_id, (
        f"concurrent merge calls disagreed on the surviving IdentityId ({surviving_id!r} vs "
        f"{result_b[1]!r}) -- interleaving corrupted the result"
    )

    lookup = ci.lookup_developer_identity(IdentityPoolId=pool_id, IdentityId=surviving_id, MaxResults=10)
    identifiers = lookup["DeveloperUserIdentifierList"]
    assert identifiers.count(src_user) == 1, (
        f"source developer identifier is not linked exactly once after concurrent merges: {identifiers!r}"
    )
    assert identifiers.count(dst_user) == 1, (
        f"destination developer identifier is not linked exactly once after concurrent merges: {identifiers!r}"
    )
    assert set(identifiers) == {dst_user, src_user}, (
        f"unexpected identifier set after concurrent merges (possible corruption): {identifiers!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
