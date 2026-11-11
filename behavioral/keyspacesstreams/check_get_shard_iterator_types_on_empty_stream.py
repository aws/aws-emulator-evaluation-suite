"""get-shard-iterator-types-on-empty-stream."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-shard-iterator-types-on-empty-stream"
GROUP = "data-plane"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TRIM_HORIZON and LATEST iterators work on a fresh empty stream and GetRecords
    returns no records; iteratorPosition starts BEHIND_TIP, reaches AT_TIP after a few
    rapid reads, and stays AT_TIP with no intervening write."""
    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "simparity-check", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_AND_OLD_IMAGES")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)
    shard_id = stream["shards"][0]["shardId"]

    for iterator_type in ("TRIM_HORIZON", "LATEST"):
        it_resp = kss.get_shard_iterator(
            streamArn=stream_arn, shardId=shard_id, shardIteratorType=iterator_type
        )
        shard_iterator = it_resp["shardIterator"]
        assert 1 <= len(shard_iterator) <= 4096, (
            f"shardIterator length {len(shard_iterator)} outside [1, 4096]"
        )

        shard_iterator = _drain_to_tip(kss, shard_iterator, iterator_type, timeout_s=60)

        # Freeze leg: once caught up, further reads with no intervening write
        # must hold AT_TIP, never regress to BEHIND_TIP.
        for _ in range(3):
            records = kss.get_records(shardIterator=shard_iterator)
            assert records["changeRecords"] == [], (
                f"expected no records on a still-empty stream, got {records['changeRecords']}"
            )
            position = records["iteratorDescription"]["iteratorPosition"]
            assert position == "AT_TIP", (
                f"{iterator_type}: expected AT_TIP to hold with no writes in between, "
                f"got {position!r} after already having caught up"
            )
            shard_iterator = records["nextShardIterator"]
            assert shard_iterator, "expected a nextShardIterator even with no records"


# ===== helpers =====


def _drain_to_tip(kss, shard_iterator: str, iterator_type: str, timeout_s: float) -> str:
    """Poll GetRecords back-to-back (no sleep -- real AWS drains the internal
    book-keeping backlog in a couple of rapid calls, but a fixed inter-call
    delay lets that backlog outrun consumption and never converges) until
    iteratorPosition reports AT_TIP. Raises if it never does."""
    deadline = time.monotonic() + timeout_s
    while True:
        records = kss.get_records(shardIterator=shard_iterator)
        assert records["changeRecords"] == [], (
            f"expected no records on a still-empty stream, got {records['changeRecords']}"
        )
        position = records["iteratorDescription"]["iteratorPosition"]
        assert position in ("AT_TIP", "BEHIND_TIP"), (
            f"{iterator_type}: unexpected iteratorPosition {position!r}"
        )
        shard_iterator = records["nextShardIterator"]
        assert shard_iterator, "expected a nextShardIterator even with no records"
        if position == "AT_TIP":
            return shard_iterator
        if time.monotonic() > deadline:
            raise AssertionError(
                f"{iterator_type}: never reached AT_TIP within {timeout_s}s on an "
                f"empty stream with no writes"
            )


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
