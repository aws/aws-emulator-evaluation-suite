"""delete-collection-while-creating-rejected."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-collection-while-creating-rejected"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCollection on a CREATING collection fails with ConflictException and its exact message and
    leaves the collection, while the same delete once it is ACTIVE answers DELETING and the collection
    then reports NOT_FOUND."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-midcreate")

    created = aoss.create_collection(
        name=name,
        type="SEARCH",
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": "delete-collection-while-creating-rejected"}],
    )["createCollectionDetail"]
    collection_id = created["id"]
    assert created["status"] == "CREATING", f"expected CREATING right after create, got {created['status']!r}"

    ctx.on_cleanup(lambda: _delete_collection(ctx, collection_id))

    # negative: deleting immediately, while still CREATING, is rejected
    current = aoss.batch_get_collection(ids=[collection_id])["collectionDetails"][0]
    if current["status"] != "CREATING":
        raise AssertionError(
            "collection left the CREATING state before the delete attempt; "
            "cannot exercise the state-conflict path deterministically"
        )
    code, message = _error_code(lambda: aoss.delete_collection(id=collection_id))
    assert code == "ConflictException", f"expected ConflictException deleting a CREATING collection, got {code!r}"
    expected = "Collection cannot be deleted because it is not in 'ACTIVE', 'FAILED', or 'UPDATE_FAILED' status."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the collection is still there, untouched by the rejected delete
    still_there = aoss.batch_get_collection(ids=[collection_id])["collectionDetails"]
    assert len(still_there) == 1, f"expected the collection to still exist, got {len(still_there)} matches"
    assert still_there[0]["id"] == collection_id, f"expected {collection_id!r}, got {still_there[0]['id']!r}"
    assert still_there[0]["status"] in ("CREATING", "ACTIVE"), (
        f"expected the rejected delete to leave the collection progressing normally, "
        f"got status {still_there[0]['status']!r}"
    )

    # positive control: once ACTIVE, the identical delete call succeeds
    _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id])["collectionDetails"],
        lambda d: bool(d) and d[0]["status"] == "ACTIVE",
        timeout_s=600,
        interval_s=15,
    )
    deleted = aoss.delete_collection(id=collection_id)["deleteCollectionDetail"]
    assert deleted["status"] == "DELETING", f"expected DELETING, got {deleted['status']!r}"
    gone = _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id]),
        lambda resp: not resp["collectionDetails"] and bool(resp.get("collectionErrorDetails")),
        timeout_s=300,
        interval_s=10,
    )
    assert gone["collectionErrorDetails"][0]["id"] == collection_id, (
        f"expected the error detail to name {collection_id!r}, got {gone['collectionErrorDetails'][0]['id']!r}"
    )
    assert gone["collectionErrorDetails"][0]["errorCode"] == "NOT_FOUND", (
        f"expected NOT_FOUND after the real delete completed, got {gone['collectionErrorDetails'][0]['errorCode']!r}"
    )


# One deadline shared by all of the check's teardowns, inside the suite's 900 s cleanup budget.
_TEARDOWN_S = 840.0
_DEADLINES: dict = {}


def _deadline(ctx) -> float:
    """The run's teardown deadline, started by its first teardown."""
    held = _DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _DEADLINES[id(ctx)] = (ctx, time.monotonic() + _TEARDOWN_S)
    return held[1]


def _delete_collection(ctx, collection_id: str) -> None:
    """Teardown: DeleteCollection, retrying every 2 s the ConflictException a collection that is not
    ACTIVE, FAILED or UPDATE_FAILED answers, then poll until BatchGetCollection no longer returns it,
    all to the shared deadline."""
    client = ctx.client("opensearchserverless")
    deadline = _deadline(ctx)
    while True:
        try:
            client.delete_collection(id=collection_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while client.batch_get_collection(ids=[collection_id]).get("collectionDetails"):
        if time.monotonic() >= deadline:
            raise AssertionError(f"collection {collection_id} still present at the teardown deadline")
        time.sleep(2)


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("DeleteCollection on a CREATING collection succeeded")


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
