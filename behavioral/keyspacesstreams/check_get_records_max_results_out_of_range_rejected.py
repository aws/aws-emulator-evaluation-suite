"""get-records-max-results-out-of-range-rejected."""
from __future__ import annotations

import re
import time

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-records-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["keyspacesstreams"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRecords rejects maxResults outside 1-1000 with ValidationException while an
    in-range value succeeds; the out-of-range calls skip client-side validation so the
    service's own rejection is what is asserted."""
    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")
    unvalidated_kss = ctx.client("keyspacesstreams", config=Config(parameter_validation=False))

    kc.create_keyspace(keyspaceName=ks)
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_IMAGE")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)
    shard_id = stream["shards"][0]["shardId"]

    iterator = kss.get_shard_iterator(
        streamArn=stream_arn, shardId=shard_id, shardIteratorType="TRIM_HORIZON"
    )["shardIterator"]

    err_zero = _error(
        lambda: unvalidated_kss.get_records(shardIterator=iterator, maxResults=0)
    )
    assert err_zero["Code"] == "ValidationException", (
        f"expected ValidationException for maxResults=0, got {err_zero['Code']}"
    )
    expected_zero = (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert err_zero["Message"] == expected_zero, (
        f"expected the message {expected_zero!r} for maxResults=0, got {err_zero['Message']!r}"
    )

    err_over = _error(
        lambda: unvalidated_kss.get_records(shardIterator=iterator, maxResults=1001)
    )
    assert err_over["Code"] == "ValidationException", (
        f"expected ValidationException for maxResults=1001, got {err_over['Code']}"
    )
    expected_over = (
        "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000"
    )
    assert err_over["Message"] == expected_over, (
        f"expected the message {expected_over!r} for maxResults=1001, got {err_over['Message']!r}"
    )

    # Positive control: an in-range maxResults succeeds.
    control = kss.get_records(shardIterator=iterator, maxResults=10)
    assert control["changeRecords"] == [], (
        f"expected no records on a fresh stream, got {control['changeRecords']}"
    )


# ===== helpers =====


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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
