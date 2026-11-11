"""delete-collection-group-nonempty-rejected."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-collection-group-nonempty-rejected"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCollectionGroup is rejected with ConflictException while it still contains a
    collection, the group is left intact, and deleting it after the collection is removed
    succeeds (positive control) in the same run."""
    aoss = ctx.client("opensearchserverless")
    group_name = _short_name(ctx, "sim2real-nonempty")
    coll_name = _short_name(ctx, "sim2real-memb")

    group_id = aoss.create_collection_group(
        name=group_name,
        standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": "nonempty-group-rejected"}],
    )["createCollectionGroupDetail"]["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_collection_group(id=group_id)))

    collection_id = aoss.create_collection(
        name=coll_name,
        type="SEARCH",
        encryptionConfig={"aWSOwnedKey": True},
        collectionGroupName=group_name,
        tags=[{"key": "sim2real", "value": "nonempty-group-rejected"}],
    )["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_collection(id=collection_id)))

    # wait for the member collection to be fully ACTIVE (not merely associated) so the
    # group's "non-empty" state is unambiguous before we probe the rejection
    _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id])["collectionDetails"],
        lambda d: bool(d) and d[0]["status"] == "ACTIVE",
        timeout_s=1500,
        interval_s=20,
    )
    _poll_until(
        lambda: aoss.batch_get_collection_group(ids=[group_id])["collectionGroupDetails"],
        lambda d: bool(d) and d[0].get("numberOfCollections", 0) >= 1,
        timeout_s=300,
        interval_s=15,
    )

    # negative: the non-empty group cannot be deleted
    code, message = _error(lambda: aoss.delete_collection_group(id=group_id))
    assert code == "ValidationException", f"unexpected error code: {code!r}"
    expected_message = f"CollectionGroup with ID {group_id}, has collections associated and cannot be deleted"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the group is still present and unaffected
    still_there = aoss.batch_get_collection_group(ids=[group_id])["collectionGroupDetails"]
    assert len(still_there) == 1, f"expected exactly the one group to still exist, got: {still_there!r}"
    assert still_there[0]["name"] == group_name, (
        f"expected name {group_name!r} unchanged after rejected delete, got: {still_there[0]['name']!r}"
    )

    # positive control: after removing the member collection, the group deletes fine
    aoss.delete_collection(id=collection_id)
    _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id]),
        lambda resp: not resp["collectionDetails"] and bool(resp.get("collectionErrorDetails")),
        timeout_s=300,
        interval_s=10,
    )
    _poll_until(
        lambda: aoss.batch_get_collection_group(ids=[group_id])["collectionGroupDetails"],
        lambda d: bool(d) and d[0].get("numberOfCollections", 1) == 0,
        timeout_s=300,
        interval_s=10,
    )
    aoss.delete_collection_group(id=group_id)
    gone = _poll_until(
        lambda: aoss.batch_get_collection_group(ids=[group_id]),
        lambda resp: not resp["collectionGroupDetails"] and bool(resp.get("collectionGroupErrorDetails")),
        timeout_s=60,
        interval_s=3,
    )
    assert gone["collectionGroupErrorDetails"][0]["errorCode"] == "NOT_FOUND", (
        f"expected the now-empty group's deletion to stick with NOT_FOUND, got: {gone!r}"
    )

    # dead id: a mutation against the deleted group also fails, not just the read
    dead_code, dead_message = _error(
        lambda: aoss.update_collection_group(id=group_id, description="dead-id-probe")
    )
    assert dead_code == "ConflictException", f"expected ConflictException for the deleted group, got {dead_code!r}"
    expected_dead = f"The CollectionGroup withId {group_id}, does not exist"
    assert dead_message == expected_dead, f"expected message {expected_dead!r}, got {dead_message!r}"


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _safe(fn: Callable[[], Any]) -> None:
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
