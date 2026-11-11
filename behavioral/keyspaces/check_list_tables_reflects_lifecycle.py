"""list-tables-reflects-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-tables-reflects-lifecycle"
GROUP = "control-plane-depth"
SERVICES = ["keyspaces"]

_SCENARIO = "list-tables-reflects-lifecycle"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTables reflects table creation and removal as they happen, not just at creation time."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_a = _kname(ctx, "sim2real_behav_a")
    tbl_b = _kname(ctx, "sim2real_behav_b")
    tag_spec = [{"key": "sim2real", "value": _SCENARIO}]

    kc.create_keyspace(keyspaceName=ks_name, tags=tag_spec)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    schema = {"allColumns": [{"name": "pk", "type": "text"}], "partitionKeys": [{"name": "pk"}]}
    _create_table_when_ready(ctx, kc, ks_name, tbl_a, schema, tags=tag_spec)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_a)))
    kc.create_table(keyspaceName=ks_name, tableName=tbl_b, schemaDefinition=schema, tags=tag_spec)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_b)))
    _wait_table_status(ctx, kc, ks_name, tbl_a, "ACTIVE", timeout_s=180.0)
    _wait_table_status(ctx, kc, ks_name, tbl_b, "ACTIVE", timeout_s=180.0)

    names = {t["tableName"] for t in kc.list_tables(keyspaceName=ks_name)["tables"]}
    assert {tbl_a, tbl_b} <= names, names

    kc.delete_table(keyspaceName=ks_name, tableName=tbl_a)
    deadline = time.monotonic() + 180.0
    removed = False
    while time.monotonic() < deadline:
        names = {t["tableName"] for t in kc.list_tables(keyspaceName=ks_name)["tables"]}
        if tbl_a not in names and tbl_b in names:
            removed = True
            break
        time.sleep(3.0)
    assert removed, f"ListTables never dropped {tbl_a} while keeping {tbl_b}, last seen: {names}"


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
