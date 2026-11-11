"""cdc-native-protocol-insert-update-delete-round-trip."""
from __future__ import annotations

import re
import ssl
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cdc-native-protocol-insert-update-delete-round-trip"
GROUP = "native-protocol"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """CQL insert/update/delete on a CDC table yield change records mirroring each
    write: NEW_IMAGE on insert, both images on update, OLD_IMAGE on delete, each
    with origin=USER and a distinct sequence number."""
    _require_cassandra_driver()

    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_AND_OLD_IMAGES")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)

    cluster, session = _cql_connect(ctx)
    ctx.on_cleanup(cluster.shutdown)

    iterators = {
        shard["shardId"]: kss.get_shard_iterator(
            streamArn=stream_arn, shardId=shard["shardId"], shardIteratorType="TRIM_HORIZON"
        )["shardIterator"]
        for shard in stream["shards"]
    }

    session.execute(
        f"INSERT INTO {ks}.{tbl} (pk, ck, val) VALUES (%s, %s, %s)", ("row1", "c1", "v1")
    )
    # The update and delete hit the same partition key, so they land in the shard the insert did.
    insert_rec, it = _next_record_across_shards(ctx, iterators)
    assert insert_rec["origin"] == "USER", f"expected origin=USER on insert, got {insert_rec['origin']!r}"
    assert insert_rec["partitionKeys"]["pk"] == {"textT": "row1"}, (
        f"expected partition key pk='row1', got {insert_rec['partitionKeys']['pk']!r}"
    )
    assert insert_rec["clusteringKeys"]["ck"] == {"textT": "c1"}, (
        f"expected clustering key ck='c1', got {insert_rec['clusteringKeys']['ck']!r}"
    )
    assert _cell_text(insert_rec["newImage"], "val") == "v1", (
        f"expected newImage.val='v1' on insert, got {_cell_text(insert_rec['newImage'], 'val')!r}"
    )
    assert insert_rec.get("oldImage") is None, (
        f"expected no oldImage on insert, got {insert_rec.get('oldImage')!r}"
    )

    session.execute(
        f"UPDATE {ks}.{tbl} SET val = %s WHERE pk = %s AND ck = %s", ("v2", "row1", "c1")
    )
    update_rec, it = _next_record(ctx, it)
    assert update_rec["sequenceNumber"] != insert_rec["sequenceNumber"], (
        "expected update to get a distinct sequenceNumber from the insert, "
        f"got the same value {update_rec['sequenceNumber']!r} for both"
    )
    assert _cell_text(update_rec["oldImage"], "val") == "v1", (
        f"expected update oldImage.val='v1', got {_cell_text(update_rec['oldImage'], 'val')!r}"
    )
    assert _cell_text(update_rec["newImage"], "val") == "v2", (
        f"expected update newImage.val='v2', got {_cell_text(update_rec['newImage'], 'val')!r}"
    )

    session.execute(f"DELETE FROM {ks}.{tbl} WHERE pk = %s AND ck = %s", ("row1", "c1"))
    delete_rec, it = _next_record(ctx, it)
    assert delete_rec["sequenceNumber"] not in (
        insert_rec["sequenceNumber"],
        update_rec["sequenceNumber"],
    ), (
        f"expected delete sequenceNumber {delete_rec['sequenceNumber']!r} to be distinct from "
        f"insert {insert_rec['sequenceNumber']!r} and update {update_rec['sequenceNumber']!r}"
    )
    assert _cell_text(delete_rec["oldImage"], "val") == "v2", (
        f"expected delete oldImage.val='v2', got {_cell_text(delete_rec['oldImage'], 'val')!r}"
    )
    assert delete_rec.get("newImage") is None, (
        f"expected no newImage on delete, got {delete_rec.get('newImage')!r}"
    )

    seqs = {insert_rec["sequenceNumber"], update_rec["sequenceNumber"], delete_rec["sequenceNumber"]}
    assert len(seqs) == 3, f"expected 3 distinct sequence numbers across insert/update/delete, got {seqs!r}"


# ===== helpers =====


def _require_cassandra_driver() -> None:
    """Import the native CQL driver up front; a missing one raises ImportError (the runner's)."""
    import cassandra.cluster  # noqa: F401
    import cassandra_sigv4.auth  # noqa: F401


def _cql_connect(ctx):
    from cassandra.cluster import Cluster
    from cassandra.query import ConsistencyLevel
    from cassandra_sigv4.auth import SigV4AuthProvider

    # Signed as ctx's own identity: the keys its keyspaces client signs with.
    creds = ctx.client("keyspaces")._request_signer._credentials.get_frozen_credentials()
    auth_provider = SigV4AuthProvider(
        aws_access_key_id=creds.access_key,
        aws_secret_access_key=creds.secret_key,
        aws_session_token=creds.token,
        region_name=ctx.region,
    )
    ssl_context = ssl.create_default_context()
    # The driver's control connection SNIs by resolved IP, not the DNS name, so the cert's
    # DNS-only SAN can never match; the connection is encrypted without verifying the
    # server's identity.
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    host, port = ctx.service_host(f"cassandra.{ctx.region}.amazonaws.com", 9142)
    cluster = Cluster([host], port=port, ssl_context=ssl_context, auth_provider=auth_provider)
    session = cluster.connect()
    # Keyspaces only supports LOCAL_QUORUM (the driver's LOCAL_ONE default is rejected
    # with an InvalidRequest at execute time).
    session.default_consistency_level = ConsistencyLevel.LOCAL_QUORUM
    return cluster, session


def _next_record_across_shards(ctx, shard_iterators: dict[str, str], timeout_s: float = 90.0):
    """A freshly enabled stream already has several shards split by token range (observed:
    4, with row1 landing in the SECOND-listed one), and which shard a partition key
    maps to is not derivable from GetStream -- so poll every shard, never assume shard 0. Returns
    the first record and the iterator of the shard it came from."""
    kss = ctx.client("keyspacesstreams")
    deadline = time.monotonic() + timeout_s
    iterators = dict(shard_iterators)
    while time.monotonic() < deadline:
        for shard_id, iterator in list(iterators.items()):
            resp = kss.get_records(shardIterator=iterator, maxResults=10)
            records = resp["changeRecords"]
            iterators[shard_id] = resp.get("nextShardIterator") or iterator
            if records:
                return records[0], iterators[shard_id]
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


def _cell_text(row: dict, column: str) -> str:
    return row["valueCells"][column]["value"]["textT"]


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
