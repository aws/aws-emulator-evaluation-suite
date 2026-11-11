"""delete-collection-group-with-collections-blocked."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-collection-group-with-collections-blocked"
GROUP = "overly-permissive"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCollectionGroup on a group holding a collection fails with ValidationException and its exact
    message and leaves the group; once the collection is gone the group deletes, as does an empty group.
    """
    osc = ctx.client("opensearchserverless")
    group_name = _short_name(ctx, "sim2real-secpolgrp-")
    collection_name = ctx.unique_name("sim2real-secpolcoll-")
    enc_policy_name = _short_name(ctx, "sim2real-secpolenc-")

    # 1. CreateCollection requires a matching encryption security policy to exist first.
    enc_doc = {
        "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
        "AWSOwnedKey": True,
    }
    osc.create_security_policy(type="encryption", name=enc_policy_name, policy=json.dumps(enc_doc))
    ctx.on_cleanup(lambda: _safe(lambda: osc.delete_security_policy(type="encryption", name=enc_policy_name)))

    # 2. Create the collection group, then place a collection inside it.
    group_id = osc.create_collection_group(
        name=group_name, standbyReplicas="DISABLED", tags=[{"key": "sim2real", "value": "audit"}]
    )["createCollectionGroupDetail"]["id"]

    def _cleanup_group():
        # best effort; if genuinely still blocked, nothing more we can do here.
        _safe(lambda: osc.delete_collection_group(id=group_id))

    ctx.on_cleanup(_cleanup_group)

    collection_id = osc.create_collection(
        name=collection_name,
        type="SEARCH",
        standbyReplicas="DISABLED",
        collectionGroupName=group_name,
        tags=[{"key": "sim2real", "value": "audit"}],
    )["createCollectionDetail"]["id"]

    def _cleanup_collection():
        _safe(lambda: osc.delete_collection(id=collection_id))
        _wait_collection_removed(osc, collection_id, timeout_s=600)

    ctx.on_cleanup(_cleanup_collection)
    _wait_collection_active(osc, collection_id, timeout_s=600)

    # Wait for the group's "non-empty" state to be unambiguous before probing the
    # rejection (membership can lag slightly behind the collection reaching ACTIVE).
    _poll_until(
        lambda: osc.batch_get_collection_group(ids=[group_id]).get("collectionGroupDetails", []),
        lambda d: bool(d) and d[0].get("numberOfCollections", 0) >= 1,
        timeout_s=300,
        interval_s=15,
    )

    # 3. Deleting the collection group while it still contains this collection
    #    must be rejected, never a silent success.
    code, message = _error(lambda: osc.delete_collection_group(id=group_id))
    assert code == "ValidationException", f"unexpected error code: {code!r}"
    expected_message = f"CollectionGroup with ID {group_id}, has collections associated and cannot be deleted"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the group must still exist afterwards, unmodified.
    still_there = osc.batch_get_collection_group(ids=[group_id]).get("collectionGroupDetails", [])
    assert len(still_there) == 1 and still_there[0]["name"] == group_name, (
        f"collection group vanished or changed despite the rejected delete: {still_there!r}"
    )

    # 4. Restore: remove the member collection, then the identical DeleteCollectionGroup
    #    call on this same group must now succeed (the six-beat negative for a
    #    state-forbids rejection: break -> assert rejection -> assert effect absent ->
    #    restore -> assert the identical call now succeeds).
    osc.delete_collection(id=collection_id)
    _wait_collection_removed(osc, collection_id, timeout_s=600)
    _poll_until(
        lambda: osc.batch_get_collection_group(ids=[group_id]).get("collectionGroupDetails", []),
        lambda d: bool(d) and d[0].get("numberOfCollections", 1) == 0,
        timeout_s=300,
        interval_s=15,
    )
    osc.delete_collection_group(id=group_id)
    restored = _poll_until(
        lambda: osc.batch_get_collection_group(ids=[group_id]),
        lambda resp: not resp.get("collectionGroupDetails")
        and bool(resp.get("collectionGroupErrorDetails")),
        timeout_s=60,
        interval_s=3,
    )
    assert restored["collectionGroupErrorDetails"][0]["errorCode"] == "NOT_FOUND", (
        f"expected the now-empty collection group deletion to stick, got: {restored!r}"
    )

    # 5. Positive control from a never-populated group: an empty collection group
    #    deletes cleanly too (a from-scratch empty group, distinct from the
    #    just-emptied one above, which could in principle have lingering state).
    empty_group_name = _short_name(ctx, "sim2real-secpolgrp2-")
    empty_group_id = osc.create_collection_group(
        name=empty_group_name, standbyReplicas="DISABLED", tags=[{"key": "sim2real", "value": "audit"}]
    )["createCollectionGroupDetail"]["id"]
    osc.delete_collection_group(id=empty_group_id)
    control_after = _poll_until(
        lambda: osc.batch_get_collection_group(ids=[empty_group_id]),
        lambda resp: not resp.get("collectionGroupDetails")
        and bool(resp.get("collectionGroupErrorDetails")),
        timeout_s=60,
        interval_s=3,
    )
    assert control_after["collectionGroupErrorDetails"][0]["errorCode"] == "NOT_FOUND", (
        f"expected the empty collection group deletion to stick, got: {control_after!r}"
    )


def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _safe(fn: Callable[[], Any]) -> None:
    """Best-effort teardown call: any error (typically not-found) is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the error ``fn`` raises. An unexpected success raises AssertionError, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last value: {last!r})")


def _wait_collection_active(osc, collection_id, timeout_s=600, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[collection_id]).get("collectionDetails", [])
        if details:
            status = details[0]["status"]
            if status == "ACTIVE":
                return
            if status == "FAILED":
                raise AssertionError(f"collection {collection_id} entered FAILED state while creating")
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} never became ACTIVE within {timeout_s}s")


def _wait_collection_removed(osc, collection_id, timeout_s=600, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[collection_id]).get("collectionDetails", [])
        if not details:
            return
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} was never fully removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
