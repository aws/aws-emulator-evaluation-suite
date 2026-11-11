"""get-shard-iterator-sequence-number-boundary-semantics."""
from __future__ import annotations

import re
import ssl
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-shard-iterator-sequence-number-boundary-semantics"
GROUP = "data-plane"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """AT_SEQUENCE_NUMBER positions the iterator inclusive of the given record;
    AFTER_SEQUENCE_NUMBER positions it exclusive, skipping straight to the next
    record in the shard."""
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

    cluster, session = _cql_connect(ctx)
    ctx.on_cleanup(cluster.shutdown)

    session.execute(
        f"INSERT INTO {ks}.{tbl} (pk, ck, val) VALUES (%s, %s, %s)", ("row1", "c1", "v1")
    )
    session.execute(
        f"INSERT INTO {ks}.{tbl} (pk, ck, val) VALUES (%s, %s, %s)", ("row1", "c2", "v2")
    )

    trim_its = {
        shard["shardId"]: kss.get_shard_iterator(
            streamArn=stream_arn, shardId=shard["shardId"], shardIteratorType="TRIM_HORIZON"
        )["shardIterator"]
        for shard in stream["shards"]
    }
    # Both rows share partition key row1, so both land in the one shard the first record names.
    shard_id, first_rec = _first_record_across_shards(ctx, trim_its)
    seq1 = first_rec["sequenceNumber"]
    assert first_rec["clusteringKeys"]["ck"] == {"textT": "c1"}, (
        f"expected TRIM_HORIZON's first record to be row1/c1, got clusteringKeys="
        f"{first_rec['clusteringKeys']!r}"
    )

    after_it = kss.get_shard_iterator(
        streamArn=stream_arn,
        shardId=shard_id,
        shardIteratorType="AFTER_SEQUENCE_NUMBER",
        sequenceNumber=seq1,
    )["shardIterator"]
    after_rec, _ = _next_record(ctx, after_it)
    assert after_rec["sequenceNumber"] != seq1, (
        f"expected AFTER_SEQUENCE_NUMBER({seq1!r}) to skip past the given record, but it "
        f"returned the same sequenceNumber {after_rec['sequenceNumber']!r}"
    )
    assert after_rec["clusteringKeys"]["ck"] == {"textT": "c2"}, (
        f"expected AFTER_SEQUENCE_NUMBER({seq1!r}) to land exclusively on row1/c2, got "
        f"clusteringKeys={after_rec['clusteringKeys']!r}"
    )

    at_it = kss.get_shard_iterator(
        streamArn=stream_arn,
        shardId=shard_id,
        shardIteratorType="AT_SEQUENCE_NUMBER",
        sequenceNumber=seq1,
    )["shardIterator"]
    at_rec, _ = _next_record(ctx, at_it)
    assert at_rec["sequenceNumber"] == seq1, (
        f"expected AT_SEQUENCE_NUMBER({seq1!r}) to be inclusive of the given record, but got "
        f"sequenceNumber {at_rec['sequenceNumber']!r}"
    )
    assert at_rec["clusteringKeys"]["ck"] == {"textT": "c1"}, (
        f"expected AT_SEQUENCE_NUMBER({seq1!r}) to land back on row1/c1, got clusteringKeys="
        f"{at_rec['clusteringKeys']!r}"
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
    ssl_context.load_default_certs()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    host, port = ctx.service_host(f"cassandra.{ctx.region}.amazonaws.com", 9142)
    cluster = Cluster(
        [host],
        port=port,
        ssl_context=ssl_context,
        ssl_options={"server_hostname": host},
        auth_provider=auth_provider,
    )
    session = cluster.connect()
    session.default_consistency_level = ConsistencyLevel.LOCAL_QUORUM
    return cluster, session


def _first_record_across_shards(ctx, shard_iterators: dict[str, str], timeout_s: float = 90.0):
    """A freshly enabled stream already has several shards split by token range (observed:
    4, with row1 landing in the SECOND-listed one, ~2s after the write), and which
    shard a partition key maps to is not derivable from GetStream -- so poll every shard, never
    assume shard 0. Returns the shard id and its first record."""
    kss = ctx.client("keyspacesstreams")
    deadline = time.monotonic() + timeout_s
    iterators = dict(shard_iterators)
    while time.monotonic() < deadline:
        for shard_id, iterator in list(iterators.items()):
            resp = kss.get_records(shardIterator=iterator, maxResults=10)
            iterators[shard_id] = resp.get("nextShardIterator") or iterator
            if resp["changeRecords"]:
                return shard_id, resp["changeRecords"][0]
        time.sleep(2)
    raise AssertionError(
        f"no change record appeared on any of {len(shard_iterators)} shard(s) within {timeout_s}s"
    )


def _next_record(ctx, shard_iterator: str, timeout_s: float = 90.0):
    kss = ctx.client("keyspacesstreams")
    deadline = time.monotonic() + timeout_s
    iterator = shard_iterator
    while time.monotonic() < deadline:
        resp = kss.get_records(shardIterator=iterator, maxResults=10)
        records = resp["changeRecords"]
        iterator = resp.get("nextShardIterator") or iterator
        if records:
            return records[0], iterator
        time.sleep(2)
    raise AssertionError("no change record appeared within timeout")


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
