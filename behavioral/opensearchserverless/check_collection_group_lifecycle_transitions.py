"""collection-group-lifecycle-transitions."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "collection-group-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CollectionGroup is created, visible via BatchGet/List, then vanishes after delete."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-cg")

    created = aoss.create_collection_group(
        name=name, standbyReplicas="DISABLED", tags=[{"key": "sim2real", "value": name}]
    )["createCollectionGroupDetail"]
    group_id = created["id"]
    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"
    assert created["standbyReplicas"] == "DISABLED", (
        f"expected standbyReplicas DISABLED, got {created['standbyReplicas']!r}"
    )

    def _cleanup() -> None:
        try:
            aoss.delete_collection_group(id=group_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = aoss.batch_get_collection_group(ids=[group_id])
    assert len(got["collectionGroupDetails"]) == 1, (
        f"expected exactly 1 detail for {group_id!r}, got {got['collectionGroupDetails']!r}"
    )
    detail = got["collectionGroupDetails"][0]
    assert detail["name"] == name, f"expected detail name {name!r}, got {detail['name']!r}"
    assert not got.get("collectionGroupErrorDetails"), (
        f"expected no error details for a live group, got {got.get('collectionGroupErrorDetails')!r}"
    )

    listed = {
        g["id"]: g for g in _list_all(aoss.list_collection_groups, "collectionGroupSummaries")
    }
    assert group_id in listed, f"expected {group_id!r} in ListCollectionGroups, got {sorted(listed)!r}"

    # representation consistency: the ListCollectionGroups summary and the
    # BatchGetCollectionGroup detail describe the same underlying resource identically
    # on the overlapping fields
    summary = listed[group_id]
    assert summary["name"] == detail["name"], (
        f"summary name {summary['name']!r} != detail name {detail['name']!r}"
    )
    assert summary["arn"] == detail["arn"], (
        f"summary arn {summary['arn']!r} != detail arn {detail['arn']!r}"
    )

    aoss.delete_collection_group(id=group_id)

    gone = _poll_until(
        lambda: aoss.batch_get_collection_group(ids=[group_id]),
        lambda resp: not resp["collectionGroupDetails"] and bool(resp.get("collectionGroupErrorDetails")),
        timeout_s=60,
        interval_s=3,
    )
    assert gone["collectionGroupErrorDetails"][0]["errorCode"] == "NOT_FOUND", (
        f"expected errorCode NOT_FOUND after delete, got {gone['collectionGroupErrorDetails'][0]!r}"
    )
    expected_item_message = "The specified Collection Group is not found."
    assert gone["collectionGroupErrorDetails"][0]["errorMessage"] == expected_item_message, (
        f"expected errorMessage {expected_item_message!r}, got {gone['collectionGroupErrorDetails'][0]!r}"
    )

    listed_after = {
        g["id"] for g in _list_all(aoss.list_collection_groups, "collectionGroupSummaries")
    }
    assert group_id not in listed_after, (
        f"expected {group_id!r} gone from ListCollectionGroups after delete, still present"
    )

    # a deleted collection group is not just absent from reads -- a second delete must
    # reject with the same not-found precondition rather than silently no-op'ing or
    # resurrecting anything
    delete_again_code, delete_again_message = _error(lambda: aoss.delete_collection_group(id=group_id))
    assert delete_again_code == "ResourceNotFoundException", (
        f"expected a second delete to reject with ResourceNotFoundException, got {delete_again_code!r}"
    )
    expected_message = f"CollectionGroup with ID '{group_id}' cannot be found."
    assert delete_again_message == expected_message, (
        f"expected message {expected_message!r}, got {delete_again_message!r}"
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


def _list_all(call: Callable[..., Any], result_key: str, **kwargs: Any) -> list[Any]:
    items: list[Any] = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = call(**params)
        items.extend(resp.get(result_key, []))
        token = resp.get("nextToken")
        if not token:
            return items


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
