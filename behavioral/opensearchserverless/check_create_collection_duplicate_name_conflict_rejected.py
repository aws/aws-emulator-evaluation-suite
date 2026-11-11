"""create-collection-duplicate-name-conflict-rejected."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-collection-duplicate-name-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCollection with a name already in use is rejected with ConflictException, the
    original collection is left exactly as it was (no duplicate created), and once that original
    is gone the identical CreateCollection call succeeds again under the same name."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-dupcol")
    state: dict[str, str] = {}
    ctx.on_cleanup(lambda: _cleanup_latest(ctx, state))

    created = aoss.create_collection(
        name=name, type="SEARCH", standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": name}],
        encryptionConfig={"aWSOwnedKey": True},
    )["createCollectionDetail"]
    collection_id = created["id"]
    state["id"] = collection_id

    # negative: creating a second collection under the same name is rejected
    code, message = _error(
        lambda: aoss.create_collection(
            name=name, type="SEARCH", encryptionConfig={"aWSOwnedKey": True}
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = f"A collection with name '{name}' already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: still exactly one collection under that name, unchanged
    got = aoss.batch_get_collection(names=[name])["collectionDetails"]
    assert len(got) == 1, f"expected exactly one persisted collection named {name!r}, got {got}"
    assert got[0]["id"] == collection_id, (
        f"expected the untouched original id {collection_id!r}, got {got[0]['id']!r}"
    )

    # restore: once the original clears out, the name is free again and the identical call
    # that was just rejected now succeeds
    active = _poll_until(
        lambda: _collection_status(aoss, collection_id),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert active == "ACTIVE", f"original collection never reached ACTIVE (last status {active!r})"
    aoss.delete_collection(id=collection_id)
    remaining = _poll_until(
        lambda: _collection_status(aoss, collection_id),
        lambda s: s == "GONE",
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert remaining == "GONE", (
        f"original collection {collection_id!r} never fully purged (last status {remaining!r})"
    )

    restored = aoss.create_collection(
        name=name, type="SEARCH", standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": name}],
        encryptionConfig={"aWSOwnedKey": True},
    )["createCollectionDetail"]
    restored_id = restored["id"]
    assert restored_id != collection_id, "restore minted the same collection id as the original"
    state["id"] = restored_id

    restored_got = aoss.batch_get_collection(names=[name])["collectionDetails"]
    assert len(restored_got) == 1, (
        f"expected exactly one persisted collection named {name!r} after restore, got {restored_got}"
    )
    assert restored_got[0]["id"] == restored_id, (
        f"expected the restored id {restored_id!r}, got {restored_got[0]['id']!r}"
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


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the AWS error ``fn`` raises; a call that succeeds fails the check."""
    try:
        fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


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


def _collection_status(client, collection_id: str) -> str:
    resp = client.batch_get_collection(ids=[collection_id])
    details = resp.get("collectionDetails", [])
    return details[0]["status"] if details else "GONE"


def _cleanup_latest(ctx, state: dict) -> None:
    collection_id = state.get("id")
    if not collection_id:
        return
    client = ctx.client("opensearchserverless")
    try:
        status = _poll_until(
            lambda: _collection_status(client, collection_id),
            lambda s: s in ("ACTIVE", "FAILED", "GONE"),
            timeout_s=900.0,
            interval_s=15.0,
        )
    except AssertionError:
        status = None
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
