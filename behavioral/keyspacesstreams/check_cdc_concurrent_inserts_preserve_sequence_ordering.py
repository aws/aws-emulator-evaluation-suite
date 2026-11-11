"""cdc-concurrent-inserts-preserve-sequence-ordering."""
from __future__ import annotations

import re
import ssl
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cdc-concurrent-inserts-preserve-sequence-ordering"
GROUP = "concurrency"
SERVICES = ["keyspacesstreams"]

_N_WRITERS = 5


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """Five concurrent CQL writers inserting distinct rows into one partition yield exactly five CDC
    change records, one per clustering key, with five distinct sequenceNumbers."""
    _require_cassandra_driver()

    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_IMAGE")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)
    # A table's CDC stream is split into multiple shards by token range (here: 4), and a
    # partition key deterministically maps to exactly one of them -- never assume shard[0]
    # is the one a given partition lands in. Read every shard and merge: whichever shard
    # covers "racepk"'s token range is the one that will actually yield records.
    iterators = {
        shard["shardId"]: kss.get_shard_iterator(
            streamArn=stream_arn, shardId=shard["shardId"], shardIteratorType="TRIM_HORIZON"
        )["shardIterator"]
        for shard in stream["shards"]
    }

    cluster, session = _cql_connect(ctx)
    ctx.on_cleanup(cluster.shutdown)

    expected_cks = {f"race-{i}" for i in range(_N_WRITERS)}

    def _write(ck: str) -> None:
        session.execute(
            f"INSERT INTO {ks}.{tbl} (pk, ck, val) VALUES (%s, %s, %s)", ("racepk", ck, ck)
        )

    with ThreadPoolExecutor(max_workers=_N_WRITERS) as pool:
        list(pool.map(_write, sorted(expected_cks)))

    records = _collect_records(ctx, iterators, expected_count=_N_WRITERS, timeout_s=90)
    got_cks = {r["clusteringKeys"]["ck"]["textT"] for r in records}
    seqs = {r["sequenceNumber"] for r in records}

    assert got_cks == expected_cks, (
        f"expected clustering keys {sorted(expected_cks)}, got {sorted(got_cks)} "
        f"(dropped={sorted(expected_cks - got_cks)}, unexpected={sorted(got_cks - expected_cks)})"
    )
    assert len(records) == _N_WRITERS, (
        f"expected exactly {_N_WRITERS} change records for {_N_WRITERS} concurrent inserts, "
        f"got {len(records)} (duplicated or dropped)"
    )
    assert len(seqs) == _N_WRITERS, (
        f"expected {_N_WRITERS} distinct sequenceNumbers, got {len(seqs)} unique "
        f"out of {len(records)} records: {[r['sequenceNumber'] for r in records]}"
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
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    host, port = ctx.service_host(f"cassandra.{ctx.region}.amazonaws.com", 9142)
    cluster = Cluster([host], port=port, ssl_context=ssl_context, auth_provider=auth_provider)
    session = cluster.connect()
    session.default_consistency_level = ConsistencyLevel.LOCAL_QUORUM
    return cluster, session


def _collect_records(ctx, shard_iterators: dict[str, str], expected_count: int, timeout_s: float):
    kss = ctx.client("keyspacesstreams")
    deadline = time.monotonic() + timeout_s
    iterators = dict(shard_iterators)
    # Every record is kept as delivered, duplicates included, so run() can count them. Reading goes
    # on until the stream is drained: the expected records arrived and a full pass over the open
    # shards returned nothing more, so a late duplicate is counted too.
    collected: list[dict] = []
    while time.monotonic() < deadline:
        got = 0
        for shard_id, iterator in list(iterators.items()):
            if iterator is None:
                continue
            resp = kss.get_records(shardIterator=iterator, maxResults=100)
            got += len(resp["changeRecords"])
            collected.extend(resp["changeRecords"])
            # No next iterator: the shard is closed and read to its end.
            iterators[shard_id] = resp.get("nextShardIterator")
        if (len(collected) >= expected_count and got == 0) or not any(iterators.values()):
            break
        time.sleep(2)
    if len(collected) < expected_count:
        raise AssertionError(
            f"only {len(collected)}/{expected_count} change records appeared within "
            f"{timeout_s}s: {[r['sequenceNumber'] for r in collected]}"
        )
    return collected


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
