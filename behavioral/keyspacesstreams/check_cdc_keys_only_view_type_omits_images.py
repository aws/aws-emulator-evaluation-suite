"""cdc-keys-only-view-type-omits-images."""
from __future__ import annotations

import re
import ssl
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cdc-keys-only-view-type-omits-images"
GROUP = "data-plane"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """A stream created with streamViewType=KEYS_ONLY records the partition/
    clustering keys of a changed row but never a newImage or oldImage, even
    though the row was written with a non-key value column."""
    _require_cassandra_driver()

    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")
    scenario = CHECK

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "sim2real", "value": scenario}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "KEYS_ONLY", scenario)
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)
    shard_ids = [s["shardId"] for s in stream["shards"]]

    cluster, session = _cql_connect(ctx)
    ctx.on_cleanup(cluster.shutdown)

    iterators = [
        kss.get_shard_iterator(
            streamArn=stream_arn, shardId=sid, shardIteratorType="TRIM_HORIZON"
        )["shardIterator"]
        for sid in shard_ids
    ]

    session.execute(
        f"INSERT INTO {ks}.{tbl} (pk, ck, val) VALUES (%s, %s, %s)", ("row1", "c1", "sensitive")
    )
    rec = _next_record_across_shards(ctx, iterators)

    assert rec["partitionKeys"]["pk"] == {"textT": "row1"}, (
        f"expected partition key pk={{'textT': 'row1'}}, got {rec['partitionKeys'].get('pk')!r}"
    )
    assert rec["clusteringKeys"]["ck"] == {"textT": "c1"}, (
        f"expected clustering key ck={{'textT': 'c1'}}, got {rec['clusteringKeys'].get('ck')!r}"
    )
    assert rec.get("newImage") is None, (
        f"KEYS_ONLY stream must never carry newImage, got {rec.get('newImage')!r}"
    )
    assert rec.get("oldImage") is None, (
        f"KEYS_ONLY stream must never carry oldImage, got {rec.get('oldImage')!r}"
    )


# ===== helpers =====


def _require_cassandra_driver() -> None:
    """Import the native CQL driver up front; a missing one raises ImportError (the runner's)."""
    import cassandra.cluster  # noqa: F401
    import cassandra_sigv4.auth  # noqa: F401


def _cql_connect(ctx):
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
    # cassandra-driver verifies the resolved peer IP against the cert SAN, not the DNS
    # name we connected with, so the connection is encrypted without verifying the server's
    # identity.
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    host, port = ctx.service_host(f"cassandra.{ctx.region}.amazonaws.com", 9142)
    cluster = Cluster([host], port=port, ssl_context=ssl_context, auth_provider=auth_provider)
    session = cluster.connect()
    # Amazon Keyspaces only accepts LOCAL_QUORUM (never the driver's LOCAL_ONE default).
    from cassandra import ConsistencyLevel

    session.default_consistency_level = ConsistencyLevel.LOCAL_QUORUM
    return cluster, session


def _next_record_across_shards(ctx, shard_iterators: list[str], timeout_s: float = 90.0) -> dict:
    """A CDC stream fans a table's writes across several shards (which shard gets a
    given row is opaque from GetStream's shard list), so a consumer must poll every
    shard rather than assume shard 0 carries the record."""
    kss = ctx.client("keyspacesstreams")
    deadline = time.monotonic() + timeout_s
    iterators = list(shard_iterators)
    while time.monotonic() < deadline:
        for i, iterator in enumerate(iterators):
            resp = kss.get_records(shardIterator=iterator, maxResults=10)
            records = resp["changeRecords"]
            iterators[i] = resp.get("nextShardIterator") or iterator
            if records:
                return records[0]
        time.sleep(2)
    raise AssertionError(
        f"no change record appeared on any of {len(shard_iterators)} shard(s) within {timeout_s}s"
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


def _create_cdc_table(ctx, keyspace: str, table: str, view_type: str, scenario: str) -> None:
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
        tags=[{"key": "sim2real", "value": scenario}],
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
