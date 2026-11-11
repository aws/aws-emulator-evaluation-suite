"""list-streams-returns-created-stream."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-streams-returns-created-stream"
GROUP = "control-plane"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStreams scoped to keyspaceName+tableName returns exactly that table's CDC
    stream, consistent with GetStream, and excludes a live CDC stream on a sibling
    table in the same keyspace."""
    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    decoy_tbl = _clean_name(ctx, "sim2realksstbldecoy")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "simparity-check", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "KEYS_ONLY")
    _create_cdc_table(ctx, ks, decoy_tbl, "KEYS_ONLY")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    decoy_stream_arn = _wait_table_cdc_status(ctx, ks, decoy_tbl, "ENABLED", timeout_s=180)
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)

    resp = kss.list_streams(keyspaceName=ks, tableName=tbl)
    assert len(resp["streams"]) == 1, (
        f"expected exactly one stream scoped to table {tbl!r} (with sibling "
        f"table {decoy_tbl!r} also CDC-enabled), got {resp['streams']!r}"
    )
    entry = resp["streams"][0]
    assert entry["streamArn"] == stream_arn, f"expected streamArn {stream_arn!r}, got {entry['streamArn']!r}"
    assert entry["streamArn"] != decoy_stream_arn, (
        f"table-scoped ListStreams returned the sibling table's stream {decoy_stream_arn!r}"
    )
    assert entry["keyspaceName"] == ks, f"expected keyspaceName {ks!r}, got {entry['keyspaceName']!r}"
    assert entry["tableName"] == tbl, f"expected tableName {tbl!r}, got {entry['tableName']!r}"
    assert entry["streamLabel"] == stream["streamLabel"], (
        f"expected streamLabel {stream['streamLabel']!r} (from GetStream), got {entry['streamLabel']!r}"
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


def _create_cdc_table(ctx, keyspace: str, table: str, view_type: str) -> None:
    kc = ctx.client("keyspaces")
    _retry_create_table(
        kc,
        keyspaceName=keyspace,
        tableName=table,
        schemaDefinition={
            "allColumns": [
                {"name": "pk", "type": "text"},
                {"name": "ck", "type": "text"},
                {"name": "val", "type": "text"},
            ],
            "partitionKeys": [{"name": "pk"}],
            "clusteringKeys": [{"name": "ck", "orderBy": "ASC"}],
        },
        capacitySpecification={"throughputMode": "PAY_PER_REQUEST"},
        cdcSpecification={"status": "ENABLED", "viewType": view_type},
        tags=[{"key": "simparity-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_best_effort(ctx, keyspace, table))


def _wait_table_cdc_status(ctx, keyspace: str, table: str, status: str, timeout_s: float) -> str:
    kc = ctx.client("keyspaces")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = kc.get_table(keyspaceName=keyspace, tableName=table)
        except kc.exceptions.ResourceNotFoundException:
            time.sleep(3)
            continue
        cdc = resp.get("cdcSpecification") or {}
        if resp.get("status") == "ACTIVE" and cdc.get("status") == status:
            return resp["latestStreamArn"]
        time.sleep(3)
    raise AssertionError(f"table/CDC did not reach ACTIVE/{status} within {timeout_s}s")


def _poll_stream_status(ctx, stream_arn: str, status: str, timeout_s: float) -> dict:
    kss = ctx.client("keyspacesstreams")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kss.get_stream(streamArn=stream_arn)
        if last["streamStatus"] == status:
            return last
        time.sleep(3)
    raise AssertionError(f"stream never reached {status}, last={last}")


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
