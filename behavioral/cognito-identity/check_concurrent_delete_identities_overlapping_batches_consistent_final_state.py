"""concurrent-delete-identities-overlapping-batches-consistent-final-state."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-identities-overlapping-batches-consistent-final-state"
GROUP = "concurrency"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent DeleteIdentities batches with overlapping identity IDs leave every one of
    the targeted identities deleted exactly once: no identity survives, and none resurfaces in
    ListIdentities afterwards."""
    cog = ctx.client("cognito-identity")

    pool_id = cog.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cid_delrace_"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identity_pool(IdentityPoolId=pool_id)))

    identity_ids = [cog.get_id(IdentityPoolId=pool_id)["IdentityId"] for _ in range(10)]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identities(IdentityIdsToDelete=identity_ids)))

    batch1 = identity_ids[0:7]
    batch2 = identity_ids[3:10]  # overlaps batch1 on indices 3-6

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(cog.delete_identities, IdentityIdsToDelete=batch1)
        f2 = pool.submit(cog.delete_identities, IdentityIdsToDelete=batch2)
        resp1 = f1.result()
        resp2 = f2.result()

    resp1_unprocessed = {u["IdentityId"] for u in resp1.get("UnprocessedIdentityIds", [])}
    resp2_unprocessed = {u["IdentityId"] for u in resp2.get("UnprocessedIdentityIds", [])}
    # Real AWS treats an overlapping delete as idempotent, not a double-processing error: neither
    # concurrent batch reports the identities it shares with the other as unprocessed.
    assert not resp1_unprocessed, f"batch1 unexpectedly reported unprocessed ids: {resp1_unprocessed}"
    assert not resp2_unprocessed, f"batch2 unexpectedly reported unprocessed ids: {resp2_unprocessed}"

    # every identity must end up deleted exactly once -- no resurrection, no survivor.
    still_alive = _poll_until_all_deleted(cog, identity_ids, timeout_s=30.0)
    assert still_alive == [], f"identities never became deleted: {still_alive}"

    listed = cog.list_identities(IdentityPoolId=pool_id, MaxResults=60)
    listed_ids = {i["IdentityId"] for i in listed.get("Identities", [])}
    assert listed_ids.isdisjoint(set(identity_ids)), (
        f"deleted identities resurfaced in ListIdentities: {listed_ids & set(identity_ids)}"
    )


# ===== helpers =====

def _safe(fn) -> None:
    """Run a teardown call; tolerate only the resource already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _poll_until_all_deleted(cog, identity_ids, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    remaining = list(identity_ids)
    while remaining and time.monotonic() < deadline:
        still = []
        for identity_id in remaining:
            try:
                cog.describe_identity(IdentityId=identity_id)
                still.append(identity_id)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        remaining = still
        if remaining:
            time.sleep(2)
    return remaining


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
