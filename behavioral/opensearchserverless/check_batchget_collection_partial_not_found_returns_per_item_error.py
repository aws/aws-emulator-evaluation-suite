"""batchget-collection-partial-not-found-returns-per-item-error."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batchget-collection-partial-not-found-returns-per-item-error"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]

_FAKE_COLLECTION_ID = "0" * 20


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetCollection with a mix of a real id and an unknown id returns the real one in
    collectionDetails and a per-item NOT_FOUND entry in collectionErrorDetails -- never a
    whole-request failure."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-bgcol")

    # CreateCollection requires an encryption policy that already matches the name.
    policy_name = _short_name(ctx, "sim2real-bgcol-enc")
    aoss.create_security_policy(
        type="encryption",
        name=policy_name,
        policy=json.dumps(
            {"Rules": [{"ResourceType": "collection", "Resource": [f"collection/{name}"]}], "AWSOwnedKey": True}
        ),
    )
    ctx.on_cleanup(lambda: _delete_encryption_policy(aoss, policy_name))

    created = aoss.create_collection(
        name=name, type="SEARCH", standbyReplicas="DISABLED"
    )["createCollectionDetail"]
    collection_id = created["id"]
    ctx.on_cleanup(lambda: _delete_collection_when_stable(ctx, collection_id))

    resp = aoss.batch_get_collection(ids=[collection_id, _FAKE_COLLECTION_ID])
    details = resp.get("collectionDetails", [])
    errors = resp.get("collectionErrorDetails", [])

    assert len(details) == 1, f"expected exactly one successful item, got {details}"
    assert details[0]["id"] == collection_id

    assert len(errors) == 1, f"expected exactly one per-item error, got {errors}"
    assert errors[0]["id"] == _FAKE_COLLECTION_ID
    assert errors[0]["errorCode"] == "NOT_FOUND"


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
    return last


def _delete_encryption_policy(client, name):
    try:
        client.delete_security_policy(type="encryption", name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_collection_when_stable(ctx, collection_id, timeout_s=900.0, interval_s=15.0):
    client = ctx.client("opensearchserverless")

    def probe():
        resp = client.batch_get_collection(ids=[collection_id])
        details = resp.get("collectionDetails", [])
        return details[0]["status"] if details else "GONE"

    status = _poll_until(
        probe, lambda s: s in ("ACTIVE", "FAILED", "GONE"), timeout_s=timeout_s, interval_s=interval_s
    )
    if status == "GONE":
        return
    if status not in ("ACTIVE", "FAILED"):
        raise AssertionError(f"collection {collection_id} still {status} after {timeout_s}s; not deleted")
    client.delete_collection(id=collection_id)
    status = _poll_until(probe, lambda s: s == "GONE", timeout_s=timeout_s, interval_s=interval_s)
    if status != "GONE":
        raise AssertionError(f"collection {collection_id} still {status} {timeout_s}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
