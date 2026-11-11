"""get-stream-nonexistent-arn-not-found."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-stream-nonexistent-arn-not-found"
GROUP = "overly-permissive"
SERVICES = ["keyspacesstreams"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetStream on a well-formed ARN of a stream that was never created is rejected
    with ResourceNotFoundException, while GetStream on the real stream succeeds."""
    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks)
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_IMAGE")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)

    bogus_arn = stream_arn.replace(f"/table/{tbl}/", "/table/s2rnonexistenttbl/")
    assert bogus_arn != stream_arn, f"expected a distinct ARN from the real one, got {bogus_arn!r}"

    err = _error(lambda: kss.get_stream(streamArn=bogus_arn))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent stream ARN, got {err['Code']!r}"
    )
    assert err["Message"] == "Requested resource not found", (
        f"expected the message 'Requested resource not found' for a nonexistent stream ARN, "
        f"got {err['Message']!r}"
    )

    # Positive control: the real stream still describes successfully.
    control = kss.get_stream(streamArn=stream_arn)
    assert control["streamArn"] == stream_arn, (
        f"expected positive control to describe {stream_arn!r}, got {control['streamArn']!r}"
    )


# ===== helpers =====


def _error(fn):
    """Call fn(); return its botocore Error member (Code and Message). An unexpected SUCCESS raises, because a
    target that ACCEPTS a call real AWS refuses is the strongest signal available and must not
    be reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


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
