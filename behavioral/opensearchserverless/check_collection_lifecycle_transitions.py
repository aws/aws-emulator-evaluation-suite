"""collection-lifecycle-transitions."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "collection-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Collection reaches ACTIVE, is visible via BatchGet/List, then is deleted and gone."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-coll")

    created = aoss.create_collection(
        name=name,
        type="SEARCH",
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": name}],
    )["createCollectionDetail"]
    collection_id = created["id"]
    assert created["status"] == "CREATING", (
        f"expected a freshly created collection to report CREATING, got {created['status']!r}"
    )

    def _cleanup() -> None:
        try:
            aoss.delete_collection(id=collection_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    details = _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id])["collectionDetails"],
        lambda d: bool(d) and d[0]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=600,
        interval_s=15,
    )
    assert details[0]["status"] == "ACTIVE", (
        f"collection {collection_id} never reached ACTIVE, last status {details[0]['status']!r}"
    )
    assert details[0]["name"] == name, (
        f"BatchGetCollection name mismatch: expected {name!r}, got {details[0]['name']!r}"
    )

    listed = {
        c["id"]: c
        for c in aoss.list_collections(collectionFilters={"name": name})["collectionSummaries"]
    }
    assert collection_id in listed, (
        f"expected {collection_id!r} in ListCollections(name={name!r}), got ids {sorted(listed)!r}"
    )
    # representation consistency: the ListCollections summary and the BatchGetCollection
    # detail describe the same underlying resource identically on the overlapping fields
    summary = listed[collection_id]
    assert summary["name"] == details[0]["name"], (
        f"ListCollections name {summary['name']!r} != BatchGetCollection name {details[0]['name']!r}"
    )
    assert summary["arn"] == details[0]["arn"], (
        f"ListCollections arn {summary['arn']!r} != BatchGetCollection arn {details[0]['arn']!r}"
    )
    assert summary["status"] == details[0]["status"], (
        f"ListCollections status {summary['status']!r} != BatchGetCollection status "
        f"{details[0]['status']!r}"
    )

    deleted = aoss.delete_collection(id=collection_id)["deleteCollectionDetail"]
    assert deleted["status"] == "DELETING", (
        f"expected DeleteCollection to report DELETING, got {deleted['status']!r}"
    )

    gone = _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id]),
        lambda resp: not resp["collectionDetails"] and bool(resp.get("collectionErrorDetails")),
        timeout_s=300,
        interval_s=10,
    )
    assert gone["collectionErrorDetails"][0]["id"] == collection_id, (
        f"expected the post-delete error detail to name {collection_id!r}, "
        f"got {gone['collectionErrorDetails'][0]['id']!r}"
    )
    assert gone["collectionErrorDetails"][0]["errorCode"] == "NOT_FOUND", (
        f"expected errorCode NOT_FOUND for deleted collection {collection_id!r}, "
        f"got {gone['collectionErrorDetails'][0]['errorCode']!r}"
    )
    not_found = "The specified Collection is not found."
    assert gone["collectionErrorDetails"][0]["errorMessage"] == not_found, (
        f"expected the exact NOT_FOUND message for deleted collection {collection_id!r}, "
        f"got {gone['collectionErrorDetails'][0]['errorMessage']!r}"
    )

    listed_after = {
        c["id"]
        for c in aoss.list_collections(collectionFilters={"name": name})["collectionSummaries"]
    }
    assert collection_id not in listed_after, (
        f"expected {collection_id!r} absent from ListCollections after delete, "
        f"still present in {sorted(listed_after)!r}"
    )


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
