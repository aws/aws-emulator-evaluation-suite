"""list-streams-pagination-across-multiple-streams."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-streams-pagination-across-multiple-streams"
GROUP = "control-plane"
SERVICES = ["keyspacesstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStreams with maxResults=1 paginates via nextToken; walking every page
    yields the full, deduplicated set of streams for the keyspace."""
    ks = _clean_name(ctx, "sim2realkssks")
    tbl1 = _clean_name(ctx, "sim2realksstblone")
    tbl2 = _clean_name(ctx, "sim2realksstbltwo")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")

    kc.create_keyspace(keyspaceName=ks)
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl1, "NEW_IMAGE")
    _create_cdc_table(ctx, ks, tbl2, "NEW_IMAGE")
    arn1 = _wait_table_cdc_status(ctx, ks, tbl1, "ENABLED", timeout_s=180)
    arn2 = _wait_table_cdc_status(ctx, ks, tbl2, "ENABLED", timeout_s=180)

    seen: dict[str, int] = {}
    next_token = None
    pages = 0
    while True:
        kwargs = {"keyspaceName": ks, "maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = kss.list_streams(**kwargs)
        pages += 1
        assert len(resp["streams"]) <= 1, (
            f"maxResults=1 but page {pages} returned {len(resp['streams'])} streams"
        )
        for entry in resp["streams"]:
            seen[entry["streamArn"]] = seen.get(entry["streamArn"], 0) + 1
        next_token = resp.get("nextToken")
        if not next_token or pages > 10:
            break

    assert seen.get(arn1) == 1, f"stream 1 ({arn1}) appeared {seen.get(arn1, 0)} times across pages, want exactly 1"
    assert seen.get(arn2) == 1, f"stream 2 ({arn2}) appeared {seen.get(arn2, 0)} times across pages, want exactly 1"
    assert pages >= 2, f"expected at least two pages when paginating two streams by 1, got {pages}"


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
