"""create-table-with-clustering-and-static-columns."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-table-with-clustering-and-static-columns"
GROUP = "control-plane-depth"
SERVICES = ["keyspaces"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A schema with a partition key, a DESC clustering key, and a static column round-trips through GetTable."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")
    res_tags = [{"key": "env", "value": "sim2real"}, {"key": "owner", "value": "behav"}]

    kc.create_keyspace(keyspaceName=ks_name, tags=res_tags)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    schema = {
        "allColumns": [
            {"name": "pk", "type": "text"},
            {"name": "ck", "type": "timestamp"},
            {"name": "meta", "type": "text"},
        ],
        "partitionKeys": [{"name": "pk"}],
        "clusteringKeys": [{"name": "ck", "orderBy": "DESC"}],
        "staticColumns": [{"name": "meta"}],
    }
    _create_table_when_ready(ctx, kc, ks_name, tbl_name, schema, tags=res_tags)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)))
    _wait_table_status(ctx, kc, ks_name, tbl_name, "ACTIVE", timeout_s=180.0)

    got = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)["schemaDefinition"]
    assert [k["name"] for k in got["partitionKeys"]] == ["pk"], got["partitionKeys"]
    assert got["clusteringKeys"] == [{"name": "ck", "orderBy": "DESC"}], got["clusteringKeys"]
    assert [c["name"] for c in got.get("staticColumns", [])] == ["meta"], got.get("staticColumns")


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_table_when_ready(ctx, kc, ks_name: str, tbl_name: str, schema: dict, timeout_s: float = 90.0, **kwargs) -> None:
    """CreateTable right after CreateKeyspace can transiently 404 until the keyspace is
    visible; retry only that specific transient condition."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.create_table(keyspaceName=ks_name, tableName=tbl_name, schemaDefinition=schema, **kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _wait_table_status(ctx, kc, ks_name: str, tbl_name: str, target: str, timeout_s: float = 180.0) -> None:
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(2.0)
            continue
        if status == target:
            return
        time.sleep(3.0)
    raise AssertionError(f"table never reached {target}, last status {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
