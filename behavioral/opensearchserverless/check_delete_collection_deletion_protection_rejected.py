"""delete-collection-deletion-protection-rejected."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-collection-deletion-protection-rejected"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCollection is rejected with ValidationException while deletionProtection is ENABLED and
    the collection is untouched; the identical delete succeeds once protection is disabled, and an
    unprotected sibling deletes normally (positive control)."""
    aoss = ctx.client("opensearchserverless")
    protected_name = _short_name(ctx, "sim2real-protcoll")
    plain_name = _short_name(ctx, "sim2real-plaincoll")

    protected_id = aoss.create_collection(
        name=protected_name,
        type="SEARCH",
        encryptionConfig={"aWSOwnedKey": True},
        deletionProtection="ENABLED",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["createCollectionDetail"]["id"]

    def _cleanup_protected() -> None:
        _safe(lambda: aoss.update_collection(id=protected_id, deletionProtection="DISABLED"))
        _safe(lambda: aoss.delete_collection(id=protected_id))

    ctx.on_cleanup(_cleanup_protected)

    plain_id = aoss.create_collection(
        name=plain_name,
        type="SEARCH",
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_collection(id=plain_id)))

    _poll_until(
        lambda: _both_statuses(aoss, protected_id, plain_id),
        lambda statuses: all(s == "ACTIVE" for s in statuses),
        timeout_s=1500,
        interval_s=20,
    )

    # negative: deleting the deletion-protected collection is rejected
    code, message = _error(lambda: aoss.delete_collection(id=protected_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        f"Collection {protected_name} cannot be deleted because deletion protection is enabled. "
        "Disable deletion protection before deleting the collection."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    # effect absent: the protected collection is still there, untouched
    still_there = aoss.batch_get_collection(ids=[protected_id])["collectionDetails"]
    assert len(still_there) == 1
    assert still_there[0]["status"] == "ACTIVE"
    assert still_there[0]["deletionProtection"] == "ENABLED"

    # restore: once deletion protection is disabled, the identical DeleteCollection call
    # on the same collection now succeeds
    aoss.update_collection(id=protected_id, deletionProtection="DISABLED")
    restored_delete = aoss.delete_collection(id=protected_id)["deleteCollectionDetail"]
    assert restored_delete["id"] == protected_id, (
        f"expected DeleteCollection to echo {protected_id!r}, got {restored_delete['id']!r}"
    )
    assert restored_delete["status"] == "DELETING", restored_delete
    _assert_purged(aoss, protected_id)

    # positive control: the sibling collection without deletion protection deletes fine
    deleted = aoss.delete_collection(id=plain_id)["deleteCollectionDetail"]
    assert deleted["id"] == plain_id, f"expected DeleteCollection to echo {plain_id!r}, got {deleted['id']!r}"
    assert deleted["status"] == "DELETING", deleted
    _assert_purged(aoss, plain_id)


# ===== self-contained helpers =====
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


def _both_statuses(aoss: Any, id1: str, id2: str) -> list[str]:
    resp = aoss.batch_get_collection(ids=[id1, id2])
    by_id = {d["id"]: d["status"] for d in resp["collectionDetails"]}
    return [by_id.get(id1, "MISSING"), by_id.get(id2, "MISSING")]


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


def _assert_purged(aoss: Any, collection_id: str) -> None:
    """Poll until BatchGetCollection reports the collection NOT_FOUND, then grade that detail."""
    gone = _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id]),
        lambda resp: not resp["collectionDetails"] and bool(resp.get("collectionErrorDetails")),
        timeout_s=600,
        interval_s=10,
    )
    expected = [
        {
            "id": collection_id,
            "errorCode": "NOT_FOUND",
            "errorMessage": "The specified Collection is not found.",
        }
    ]
    assert gone["collectionErrorDetails"] == expected, (
        f"expected {expected!r}, got {gone['collectionErrorDetails']!r}"
    )


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
