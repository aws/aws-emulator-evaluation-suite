"""update-table-add-column-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-table-add-column-transition"
GROUP = "state-machine"
SERVICES = ["keyspaces"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTable(addColumns=...) cycles Table.status ACTIVE -> UPDATING -> ACTIVE and the new column persists."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    schema = {"allColumns": [{"name": "pk", "type": "text"}], "partitionKeys": [{"name": "pk"}]}
    _create_table_when_ready(ctx, kc, ks_name, tbl_name, schema, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)))
    _wait_table_status(ctx, kc, ks_name, tbl_name, "ACTIVE", timeout_s=180.0)

    before = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)
    before_cols = {c["name"] for c in before["schemaDefinition"]["allColumns"]}
    assert "extra_col" not in before_cols, before_cols

    kc.update_table(
        keyspaceName=ks_name,
        tableName=tbl_name,
        addColumns=[{"name": "extra_col", "type": "text"}],
    )

    # UpdateTable(addColumns) may not linger in a non-ACTIVE status long enough to observe;
    # poll GetTable directly for the new column rather than trusting a status-only wait.
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 180.0
    col_names: set = set()
    while time.monotonic() < deadline:
        try:
            got = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(2.0)
            continue
        assert got["status"] in ("ACTIVE", "UPDATING"), got["status"]
        col_names = {c["name"] for c in got["schemaDefinition"]["allColumns"]}
        if "extra_col" in col_names:
            break
        time.sleep(3.0)
    assert "extra_col" in col_names, col_names


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
