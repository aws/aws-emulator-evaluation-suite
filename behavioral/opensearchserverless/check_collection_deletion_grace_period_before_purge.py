"""collection-deletion-grace-period-before-purge."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "collection-deletion-grace-period-before-purge"
GROUP = "visibility-timeout-ttl"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCollection and an immediate BatchGetCollection report DELETING; once purged, BatchGetCollection
    returns a NOT_FOUND error detail with its exact message and ListCollections omits the collection.
    """
    client = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-cdel-")

    detail = client.create_collection(
        name=name,
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": "collection-deletion-grace-period-before-purge"}],
    )["createCollectionDetail"]
    collection_id = detail["id"]
    ctx.on_cleanup(lambda: _safe_delete(client, collection_id))

    status = _poll_until(
        lambda: _collection_status(client, collection_id),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    assert status == "ACTIVE", f"collection never reached ACTIVE (last status {status!r})"

    del_detail = client.delete_collection(id=collection_id)["deleteCollectionDetail"]
    assert del_detail["status"] == "DELETING", (
        f"expected DeleteCollection to report DELETING, got {del_detail['status']!r}"
    )

    # The collection must remain visible (in DELETING state) for a grace window right after
    # DeleteCollection returns, rather than vanishing instantly.
    immediate = client.batch_get_collection(ids=[collection_id])
    immediate_details = immediate.get("collectionDetails", [])
    assert len(immediate_details) == 1, (
        f"collection should still be visible immediately after DeleteCollection, got {immediate_details}"
    )
    assert immediate_details[0]["status"] == "DELETING", (
        f"collection should report DELETING immediately after delete, got {immediate_details[0]['status']!r}"
    )

    gone = _poll_until(
        lambda: client.batch_get_collection(ids=[collection_id]),
        lambda resp: not resp.get("collectionDetails") and bool(resp.get("collectionErrorDetails")),
        timeout_s=900,
        interval_s=15,
    )
    assert not gone.get("collectionDetails"), (
        f"collection is still present in BatchGetCollection after the purge window: {gone}"
    )
    error_details = gone.get("collectionErrorDetails") or []
    assert len(error_details) == 1 and error_details[0]["id"] == collection_id, (
        f"expected exactly one BatchGetCollection error detail for {collection_id!r}, got {error_details}"
    )
    assert error_details[0]["errorCode"] == "NOT_FOUND", (
        f"expected errorCode NOT_FOUND once purged, got {error_details[0]!r}"
    )
    not_found = "The specified Collection is not found."
    assert error_details[0]["errorMessage"] == not_found, (
        f"expected the exact NOT_FOUND message once purged, got {error_details[0]!r}"
    )

    summaries = client.list_collections().get("collectionSummaries", [])
    assert collection_id not in {s["id"] for s in summaries}


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _collection_status(client, collection_id):
    resp = client.batch_get_collection(ids=[collection_id])
    details = resp.get("collectionDetails", [])
    return details[0]["status"] if details else "GONE"


def _safe_delete(client, collection_id):
    try:
        client.delete_collection(id=collection_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
