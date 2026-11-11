"""stream-enabled-after-cdc-create."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stream-enabled-after-cdc-create"
GROUP = "state-transitions"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enabling CDC on a new Keyspaces table drives streamStatus ENABLING -> ENABLED
    and GetStream exposes a coherent, matching stream description."""
    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_AND_OLD_IMAGES")

    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)

    # Poll GetStream until it independently reports ENABLED too (the two control
    # planes -- table CDC summary and the stream resource itself -- must agree).
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)

    assert stream["streamArn"] == stream_arn, (
        f"GetStream arn mismatch: expected {stream_arn}, got {stream['streamArn']}"
    )
    assert stream["keyspaceName"] == ks, (
        f"stream keyspaceName mismatch: expected {ks}, got {stream['keyspaceName']}"
    )
    assert stream["tableName"] == tbl, (
        f"stream tableName mismatch: expected {tbl}, got {stream['tableName']}"
    )
    assert stream["streamViewType"] == "NEW_AND_OLD_IMAGES", (
        f"streamViewType mismatch: expected NEW_AND_OLD_IMAGES, got {stream['streamViewType']}"
    )
    assert stream["streamLabel"] and stream_arn.endswith(stream["streamLabel"]), (
        f"streamArn {stream_arn!r} does not end with streamLabel {stream.get('streamLabel')!r}"
    )
    shards = stream["shards"]
    assert len(shards) >= 1, f"expected at least one shard on a freshly enabled stream, got {shards!r}"
    for shard in shards:
        assert 28 <= len(shard["shardId"]) <= 65, (
            f"shardId {shard['shardId']!r} length {len(shard['shardId'])} outside [28, 65]"
        )
        assert "startingSequenceNumber" in shard["sequenceNumberRange"], (
            f"shard {shard['shardId']!r} sequenceNumberRange missing startingSequenceNumber: "
            f"{shard['sequenceNumberRange']!r}"
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
        tags=[{"key": "sim2real", "value": CHECK}],
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
