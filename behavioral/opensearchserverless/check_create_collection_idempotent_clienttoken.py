"""create-collection-idempotent-clienttoken."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-collection-idempotent-clienttoken"
GROUP = "ordering"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeating CreateCollection with the same clientToken dedupes to the original collection."""
    client = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-coll-")
    token = str(uuid.uuid4())

    # CreateCollection requires a matching encryption security policy to exist first
    # ("No matching security policy of encryption type found for collection").
    enc_policy_name = _short_name(ctx, "sim2real-cidenc-")
    enc_doc = {"Rules": [{"ResourceType": "collection", "Resource": [f"collection/{name}"]}], "AWSOwnedKey": True}
    client.create_security_policy(type="encryption", name=enc_policy_name, policy=json.dumps(enc_doc))
    ctx.on_cleanup(lambda: _teardown(lambda: client.delete_security_policy(type="encryption", name=enc_policy_name)))

    resp1 = client.create_collection(name=name, clientToken=token, tags=[{"key": "sim2real", "value": CHECK}])
    detail1 = resp1["createCollectionDetail"]
    collection_id = detail1["id"]
    ctx.on_cleanup(lambda: _delete_collection_when_stable(ctx, collection_id))

    resp2 = client.create_collection(name=name, clientToken=token, tags=[{"key": "sim2real", "value": CHECK}])
    detail2 = resp2["createCollectionDetail"]

    assert detail2["id"] == collection_id, (
        f"repeating CreateCollection with the same clientToken should return the same "
        f"collection id, got {detail1['id']!r} then {detail2['id']!r}"
    )

    # Confirm no duplicate collection was actually created under that name.
    batch = client.batch_get_collection(names=[name])
    details = batch.get("collectionDetails", [])
    assert len(details) == 1, f"expected exactly one collection named {name!r}, got {details}"
    assert details[0]["id"] == collection_id, (
        f"batch_get_collection for {name!r} returned id {details[0]['id']!r}, expected {collection_id!r}"
    )


# ===== self-contained helpers =====
def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _teardown(fn, timeout_s=200.0):
    """Teardown call: an absent resource is done, ConflictException (a collection still CREATING)
    or ValidationException (a policy still in use) is retried every 2 s to the deadline, which
    keeps all of the check's teardowns inside its cleanup budget; every other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _delete_collection_when_stable(ctx, collection_id, timeout_s=360.0, interval_s=2.0):
    client = ctx.client("opensearchserverless")

    def probe():
        resp = client.batch_get_collection(ids=[collection_id])
        details = resp.get("collectionDetails", [])
        return details[0]["status"] if details else "GONE"

    status = _poll_until(probe, lambda s: s in ("ACTIVE", "FAILED", "GONE"), timeout_s, interval_s)
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
