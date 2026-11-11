"""list-streams-filtered-empty-for-table-without-cdc."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-streams-filtered-empty-for-table-without-cdc"
GROUP = "control-plane"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStreams filtered by keyspaceName+tableName does not validate the filter: a
    table without CDC and a keyspace/table that does not exist both return an empty
    list rather than ResourceNotFoundException."""
    ks = _clean_name(ctx, "sim2realkssks")
    plain_tbl = _clean_name(ctx, "sim2realssplaintbl")
    missing_ks = _clean_name(ctx, "sim2realkssmissingks")
    missing_tbl = _clean_name(ctx, "sim2realssmissingtbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks)
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))

    _retry_create_table(
        kc,
        keyspaceName=ks,
        tableName=plain_tbl,
        schemaDefinition={
            "allColumns": [{"name": "pk", "type": "text"}],
            "partitionKeys": [{"name": "pk"}],
        },
        capacitySpecification={"throughputMode": "PAY_PER_REQUEST"},
    )
    ctx.on_cleanup(lambda: _delete_table_best_effort(ctx, ks, plain_tbl))
    _wait_table_active(ctx, ks, plain_tbl, timeout_s=180)

    resp = kss.list_streams(keyspaceName=ks, tableName=plain_tbl)
    assert resp["streams"] == [], (
        f"expected no streams for a table that never had CDC enabled, got {resp['streams']}"
    )

    assert missing_ks != ks and missing_tbl != plain_tbl, (
        "unique name generator collided with itself"
    )
    missing_resp = kss.list_streams(keyspaceName=missing_ks, tableName=missing_tbl)
    assert missing_resp["streams"] == [], (
        "expected no streams (and no error) for a keyspace/table that was never "
        f"created, got {missing_resp['streams']}"
    )


# ===== helpers =====


def _clean_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return re.sub(r"[^a-zA-Z0-9_]", "", raw)[:48]


def _retry_create_table(kc, timeout_s: float = 60, **kwargs) -> None:
    """CreateTable can trail CreateKeyspace by a few seconds while the new
    keyspace propagates; retry on ResourceNotFoundException instead of
    failing immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.create_table(**kwargs)
            return
        except kc.exceptions.ResourceNotFoundException:
            if time.monotonic() > deadline:
                raise
            time.sleep(3)


def _wait_table_active(ctx, keyspace: str, table: str, timeout_s: float) -> None:
    kc = ctx.client("keyspaces")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = kc.get_table(keyspaceName=keyspace, tableName=table)
        except kc.exceptions.ResourceNotFoundException:
            time.sleep(3)
            continue
        if resp.get("status") == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"table did not become ACTIVE within {timeout_s}s")


def _delete_table_best_effort(ctx, keyspace: str, table: str) -> None:
    kc = ctx.client("keyspaces")
    try:
        kc.delete_table(keyspaceName=keyspace, tableName=table)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_keyspace_best_effort(ctx, keyspace: str) -> None:
    kc = ctx.client("keyspaces")
    deadline = time.monotonic() + 120
    while True:
        try:
            kc.delete_keyspace(keyspaceName=keyspace)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # A table delete still in progress refuses the keyspace delete; retry to the deadline.
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
