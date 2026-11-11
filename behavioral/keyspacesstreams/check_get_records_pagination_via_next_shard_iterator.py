"""get-records-pagination-via-next-shard-iterator."""
from __future__ import annotations

import re
import ssl
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-records-pagination-via-next-shard-iterator"
GROUP = "data-plane"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """GetRecords honors maxResults (never returns more than requested) and
    walking nextShardIterator forward, one record at a time, eventually collects
    every row written -- with no duplicates -- in the order they were written."""
    _require_cassandra_driver()

    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "sim2real-check", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_IMAGE")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)

    cluster, session = _cql_connect(ctx)
    ctx.on_cleanup(cluster.shutdown)

    expected_cks = ["c1", "c2", "c3"]
    for ck in expected_cks:
        session.execute(
            f"INSERT INTO {ks}.{tbl} (pk, ck, val) VALUES (%s, %s, %s)", ("row1", ck, ck)
        )

    # The stream is split into several shards by token range; the one partition key lands on
    # one of them, so every shard is walked and their records are collected per shard.
    iterators = {
        shard["shardId"]: kss.get_shard_iterator(
            streamArn=stream_arn, shardId=shard["shardId"], shardIteratorType="TRIM_HORIZON"
        )["shardIterator"]
        for shard in stream["shards"]
    }

    per_shard: dict[str, list[str]] = {shard_id: [] for shard_id in iterators}
    collected_cks: list[str] = []
    seen_seq: set[str] = set()
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline and len(collected_cks) < len(expected_cks):
        got_any = False
        for shard_id, it in list(iterators.items()):
            resp = kss.get_records(shardIterator=it, maxResults=1)
            assert len(resp["changeRecords"]) <= 1, (
                f"maxResults=1 but GetRecords returned {len(resp['changeRecords'])} changeRecords"
            )
            for rec in resp["changeRecords"]:
                got_any = True
                if rec["sequenceNumber"] not in seen_seq:
                    seen_seq.add(rec["sequenceNumber"])
                    per_shard[shard_id].append(rec["clusteringKeys"]["ck"]["textT"])
            iterators[shard_id] = resp.get("nextShardIterator") or it
        collected_cks = [ck for cks in per_shard.values() for ck in cks]
        if not got_any:
            time.sleep(2)

    assert collected_cks == expected_cks, (
        f"expected clustering keys {expected_cks} in write order, got {collected_cks}"
    )
    assert len(seen_seq) == len(expected_cks), (
        f"expected {len(expected_cks)} unique sequenceNumbers, got {len(seen_seq)} "
        f"(collected_cks={collected_cks})"
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
    # cassandra-driver's own connection pool dials the resolved IP directly, so
    # SNI/hostname checking would compare the cert against an IP literal and
    # always fail; the connection is encrypted without verifying the server's identity.
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    host, port = ctx.service_host(f"cassandra.{ctx.region}.amazonaws.com", 9142)
    cluster = Cluster([host], port=port, ssl_context=ssl_context, auth_provider=auth_provider)
    session = cluster.connect()
    # Keyspaces rejects the driver's default LOCAL_ONE consistency for writes;
    # LOCAL_QUORUM is the level Keyspaces documents as supported.
    from cassandra import ConsistencyLevel

    session.default_consistency_level = ConsistencyLevel.LOCAL_QUORUM
    return cluster, session


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
        tags=[{"key": "sim2real-check", "value": CHECK}],
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
