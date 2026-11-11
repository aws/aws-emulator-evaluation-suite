"""update-collection-concurrent-modification-resolves-consistently."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-collection-concurrent-modification-resolves-consistently"
GROUP = "concurrency"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateCollection calls either both succeed, leaving the description and lastModifiedDate of
    the later write, or the loser fails with ConflictException; a later update then persists.
    """
    client = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-upd-")

    created = client.create_collection(
        name=name,
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": "update-collection-concurrent-modification"}],
    )["createCollectionDetail"]
    collection_id = created["id"]
    ctx.on_cleanup(lambda: _delete_collection_when_stable(ctx, collection_id))

    status = _poll_until(
        lambda: _collection_status(client, collection_id),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    assert status == "ACTIVE", f"collection never reached ACTIVE (last status {status!r})"

    def attempt(description):
        try:
            resp = client.update_collection(id=collection_id, description=description)["updateCollectionDetail"]
            return (description, "ok", resp["lastModifiedDate"])
        except ClientError as err:
            return (description, "err", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            f.result()
            for f in [
                pool.submit(attempt, "concurrent-update-a"),
                pool.submit(attempt, "concurrent-update-b"),
            ]
        ]

    for description, kind, payload in results:
        if kind == "err":
            assert payload == "ConflictException", (
                f"expected a losing concurrent UpdateCollection ({description!r}) to fail with "
                f"ConflictException specifically, got {payload!r}"
            )

    oks = [(description, modified) for description, kind, modified in results if kind == "ok"]
    assert len(oks) >= 1, f"expected at least one concurrent update to succeed, got {results}"

    # Wait for the winning update to settle back to ACTIVE before checking persisted state.
    settled = _poll_until(
        lambda: _collection_status(client, collection_id),
        lambda s: s in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    assert settled == "ACTIVE", f"collection did not settle back to ACTIVE (status {settled!r})"

    got = client.batch_get_collection(ids=[collection_id])["collectionDetails"][0]
    if len(oks) == 2:
        # Two writes in the same millisecond report the same lastModifiedDate, so the winner is the
        # persisted one; a strictly later write must be the one that persisted.
        modified = dict(oks)
        assert got["description"] in modified, (
            f"the persisted description {got['description']!r} is neither concurrent update's {oks}"
        )
        winner_description = got["description"]
        winner_modified = modified[winner_description]
        loser_description, loser_modified = next(r for r in oks if r[0] != winner_description)
        assert winner_modified >= loser_modified, (
            f"the update that persisted ({winner_description!r}) reports lastModifiedDate "
            f"{winner_modified!r}, earlier than the other update's {loser_modified!r}"
        )
    else:
        winner_description, winner_modified = oks[0]
        loser_description = next(description for description, kind, _ in results if kind == "err")
    assert got["description"] == winner_description, (
        f"expected the persisted description to be the winning update's "
        f"({winner_description!r}), got {got['description']!r}"
    )
    assert got["description"] != loser_description, (
        f"the losing concurrent update's description ({loser_description!r}) must not have persisted"
    )
    assert got["lastModifiedDate"] == winner_modified, (
        f"expected persisted lastModifiedDate to match the winning update's own reported value "
        f"({winner_modified!r}), got {got['lastModifiedDate']!r}"
    )

    # Positive control: a follow-up update against the now-settled collection still succeeds.
    final_status = _poll_until(
        lambda: _try_update(client, collection_id, "settled-update"),
        lambda outcome: outcome is not None,
        timeout_s=120,
        interval_s=5,
    )
    assert final_status == "settled-update", (
        f"expected a follow-up update against the settled collection to succeed, got {final_status!r}"
    )

    # Terminal read: an independent read (batch_get, never the mutating call's own response)
    # confirms the follow-up write actually persisted.
    final_read = client.batch_get_collection(ids=[collection_id])["collectionDetails"][0]
    assert final_read["description"] == "settled-update", (
        f"expected the follow-up update to persist at an independent read, got "
        f"{final_read['description']!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _collection_status(client, collection_id):
    resp = client.batch_get_collection(ids=[collection_id])
    details = resp.get("collectionDetails", [])
    return details[0]["status"] if details else "GONE"


def _try_update(client, collection_id, description):
    try:
        resp = client.update_collection(id=collection_id, description=description)
        return resp["updateCollectionDetail"]["description"]
    except ClientError:
        return None


def _delete_collection_when_stable(ctx, collection_id, timeout_s=900.0, interval_s=15.0):
    client = ctx.client("opensearchserverless")
    status = _poll_until(
        lambda: _collection_status(client, collection_id),
        lambda s: s in ("ACTIVE", "FAILED", "GONE"),
        timeout_s,
        interval_s,
    )
    if status == "GONE":
        return
    try:
        client.delete_collection(id=collection_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
