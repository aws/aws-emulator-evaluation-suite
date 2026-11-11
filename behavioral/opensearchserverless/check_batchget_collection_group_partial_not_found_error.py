"""batchget-collection-group-partial-not-found-error."""
from __future__ import annotations

import re
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batchget-collection-group-partial-not-found-error"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]

_FAKE_GROUP_ID = "1" * 20


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetCollectionGroup with a mix of a real id and an unknown id returns the real group
    in collectionGroupDetails and a per-item NOT_FOUND entry in collectionGroupErrorDetails."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-bggrp")

    created = aoss.create_collection_group(
        name=name,
        standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": "batchget-collection-group-partial-not-found-error"}],
    )["createCollectionGroupDetail"]
    group_id = created["id"]
    assert created["name"] == name, f"expected name {name!r}, got {created['name']!r}"

    def _cleanup() -> None:
        try:
            aoss.delete_collection_group(id=group_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    resp = aoss.batch_get_collection_group(ids=[group_id, _FAKE_GROUP_ID])
    details = resp.get("collectionGroupDetails", [])
    errors = resp.get("collectionGroupErrorDetails", [])

    assert len(details) == 1, f"expected exactly one successful item, got {details}"
    assert details[0]["id"] == group_id, f"expected {group_id!r}, got {details[0]['id']!r}"

    assert len(errors) == 1, f"expected exactly one per-item error, got {errors}"
    assert errors[0]["id"] == _FAKE_GROUP_ID, f"expected error id {_FAKE_GROUP_ID!r}, got {errors[0]!r}"
    assert errors[0]["errorCode"] == "NOT_FOUND", f"expected NOT_FOUND, got {errors[0]['errorCode']!r}"


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
