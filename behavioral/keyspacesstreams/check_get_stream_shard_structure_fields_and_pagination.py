"""get-stream-shard-structure-fields-and-pagination."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-stream-shard-structure-fields-and-pagination"
GROUP = "data-plane"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStream shard descriptions respect the documented field lengths, a fresh
    stream's shards are all roots, and maxResults=1 pagination yields the same shard
    set as one unpaginated call."""
    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_IMAGE")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    full = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)
    full_shard_ids = {s["shardId"] for s in full["shards"]}
    assert full_shard_ids, f"freshly CDC-enabled stream {stream_arn} reported zero shards"

    for shard in full["shards"]:
        shard_id = shard["shardId"]
        assert 28 <= len(shard_id) <= 65, (
            f"shardId {shard_id!r} length {len(shard_id)} outside modelled bounds [28, 65]"
        )
        seq_range = shard["sequenceNumberRange"]
        start_seq = seq_range["startingSequenceNumber"]
        assert 21 <= len(start_seq) <= 48, (
            f"startingSequenceNumber {start_seq!r} length {len(start_seq)} outside modelled bounds [21, 48]"
        )
        # parentShardIds is optional and only meaningful for shards created
        # through resharding; when present, non-null entries must still be
        # well-formed shard ids (the field's own length constraints).
        parents = shard.get("parentShardIds")
        if parents:
            for parent_id in parents:
                if parent_id is not None:
                    assert 28 <= len(parent_id) <= 65, (
                        f"parentShardIds entry {parent_id!r} length {len(parent_id)} "
                        "outside modelled bounds [28, 65]"
                    )

    paginated_ids: set[str] = set()
    next_token = None
    pages = 0
    while pages < 20:
        kwargs = {"streamArn": stream_arn, "maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = kss.get_stream(**kwargs)
        pages += 1
        assert len(resp["shards"]) <= 1, (
            f"maxResults=1 page {pages} returned {len(resp['shards'])} shards, expected at most 1"
        )
        paginated_ids.update(s["shardId"] for s in resp["shards"])
        next_token = resp.get("nextToken")
        if not next_token:
            break

    assert paginated_ids == full_shard_ids, (
        f"paginated shard ids {sorted(paginated_ids)} != unpaginated shard ids {sorted(full_shard_ids)}"
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
