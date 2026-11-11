"""cdc-batch-operation-decomposes-into-row-records."""
from __future__ import annotations

import re
import ssl
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cdc-batch-operation-decomposes-into-row-records"
GROUP = "data-plane"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """A CQL BATCH of two INSERTs (same partition, two rows) becomes two row-level
    change records, each independently sequenced with origin=USER; BATCH guarantees
    atomicity but no order between its statements, so the set of rows is asserted."""
    _require_cassandra_driver()

    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "simparity-check", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_IMAGE")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)
    # A freshly enabled stream already has multiple shards (token-range
    # partitioned, like Kinesis/DynamoDB streams) -- which one a given
    # partition key lands in is not derivable from the API, so every shard
    # needs an iterator and every shard needs polling.
    shard_ids = [s["shardId"] for s in stream["shards"]]

    cluster, session = _cql_connect(ctx)
    ctx.on_cleanup(cluster.shutdown)

    iterators = {
        shard_id: kss.get_shard_iterator(
            streamArn=stream_arn, shardId=shard_id, shardIteratorType="TRIM_HORIZON"
        )["shardIterator"]
        for shard_id in shard_ids
    }

    batch_cql = (
        "BEGIN BATCH "
        f"INSERT INTO {ks}.{tbl} (pk, ck, val) VALUES ('row1', 'b1', 'first'); "
        f"INSERT INTO {ks}.{tbl} (pk, ck, val) VALUES ('row1', 'b2', 'second'); "
        "APPLY BATCH;"
    )
    session.execute(batch_cql)
    rows = list(session.execute(f"SELECT pk, ck, val FROM {ks}.{tbl}"))
    assert len(rows) == 2, f"expected the batch to have written 2 rows, CQL read back {rows!r}"

    records = _collect_records(kss, iterators, expected_count=2, timeout_s=90)
    assert len(records) == 2, f"expected exactly 2 change records for the 2-statement batch, got {len(records)}: {records}"
    got_cks = {rec["clusteringKeys"]["ck"]["textT"] for rec in records}
    assert got_cks == {"b1", "b2"}, (
        f"expected the batch to decompose into one record per row (ck=b1 and ck=b2), "
        f"got {got_cks!r}"
    )
    assert records[0]["sequenceNumber"] != records[1]["sequenceNumber"], (
        f"expected each decomposed row-record to get its own sequenceNumber, "
        f"both were {records[0]['sequenceNumber']!r}"
    )
    assert all(r["origin"] == "USER" for r in records), (
        f"expected origin=USER on every decomposed record, got "
        f"{[r['origin'] for r in records]}"
    )


# ===== helpers =====


def _require_cassandra_driver() -> None:
    """Import the native CQL driver up front; a missing one raises ImportError (the runner's)."""
    import cassandra.cluster  # noqa: F401
    import cassandra_sigv4.auth  # noqa: F401


def _cql_connect(ctx):
    from cassandra import ConsistencyLevel
    from cassandra.cluster import Cluster
    from cassandra_sigv4.auth import SigV4AuthProvider

    # Signed as ctx's own identity: the keys its keyspaces client signs with.
    creds = ctx.client("keyspaces")._request_signer._credentials.get_frozen_credentials()
    auth_provider = SigV4AuthProvider(
        aws_access_key_id=creds.access_key,
        aws_secret_access_key=creds.secret_key,
        aws_session_token=creds.token,
        region_name=ctx.region,
    )
    # Encrypted, without verifying the server's identity.
    ssl_context = ssl._create_unverified_context()
    host, port = ctx.service_host(f"cassandra.{ctx.region}.amazonaws.com", 9142)
    # cassandra-driver's control connection resolves the contact point to an
    # IP once, then reuses that IP as `Host.address`; when it later reconnects
    # (e.g. after Keyspaces' CQL peer discovery returns per-connection IPs),
    # connection.py defaults SNI/hostname-check to that IP instead of the DNS
    # name the cert is actually issued for. Pinning server_hostname keeps SNI on the
    # real DNS name on every connection regardless of which IP it lands on.
    cluster = Cluster(
        [host],
        port=port,
        ssl_context=ssl_context,
        ssl_options={"server_hostname": host},
        auth_provider=auth_provider,
    )
    session = cluster.connect()
    # Keyspaces rejects writes at the driver's default LOCAL_ONE with
    # "Consistency level LOCAL_ONE is not supported for this operation";
    # LOCAL_QUORUM is the level Keyspaces actually supports for writes.
    session.default_consistency_level = ConsistencyLevel.LOCAL_QUORUM
    return cluster, session


def _collect_records(kss, iterators: dict, expected_count: int, timeout_s: float):
    """Poll every shard's iterator (a written partition key can land in any
    shard of a token-range-partitioned stream) and return the records from
    whichever single shard actually received them, in that shard's order."""
    deadline = time.monotonic() + timeout_s
    per_shard: dict[str, list[dict]] = {shard_id: [] for shard_id in iterators}
    seen: set[str] = set()
    while time.monotonic() < deadline and sum(len(v) for v in per_shard.values()) < expected_count:
        for shard_id, iterator in list(iterators.items()):
            resp = kss.get_records(shardIterator=iterator, maxResults=100)
            for rec in resp["changeRecords"]:
                if rec["sequenceNumber"] not in seen:
                    seen.add(rec["sequenceNumber"])
                    per_shard[shard_id].append(rec)
            iterators[shard_id] = resp.get("nextShardIterator") or iterator
    non_empty = {shard_id: recs for shard_id, recs in per_shard.items() if recs}
    total = sum(len(v) for v in per_shard.values())
    if total < expected_count:
        raise AssertionError(
            f"expected {expected_count} change record(s) across {len(iterators)} shard(s) "
            f"within {timeout_s}s, got only {total}: {per_shard!r}"
        )
    assert len(non_empty) == 1, (
        f"expected both rows of the batch (same partition key) to land in exactly one "
        f"shard, got records spread across {len(non_empty)} shard(s): {non_empty!r}"
    )
    return next(iter(non_empty.values()))


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
