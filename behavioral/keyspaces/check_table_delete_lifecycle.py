"""table-delete-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "table-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["keyspaces"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTable moves an ACTIVE table through DELETING until GetTable/ListTables no longer show it."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")
    scenario = "table-delete-lifecycle"

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": scenario}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    schema = {"allColumns": [{"name": "pk", "type": "text"}], "partitionKeys": [{"name": "pk"}]}
    _create_table_when_ready(ctx, kc, ks_name, tbl_name, schema,
                              tags=[{"key": "sim2real", "value": scenario}])
    _wait_table_status(ctx, kc, ks_name, tbl_name, "ACTIVE", timeout_s=180.0)

    kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)

    from botocore.exceptions import ClientError
    delete_issued_at = time.monotonic()
    grace_deadline = delete_issued_at + 20.0  # brief eventual-consistency window where ACTIVE may still show
    deadline = delete_issued_at + 180.0
    gone = False
    left_active = False
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                gone = True
                break
            raise
        if last_status == "ACTIVE":
            assert not left_active, "table status reverted back to ACTIVE after leaving it during delete"
            assert time.monotonic() < grace_deadline, "table still ACTIVE well after DeleteTable was issued"
        else:
            assert last_status in ("DELETING", "DELETED"), last_status
            left_active = True
        time.sleep(3.0)
    assert gone, f"table was never fully removed, last observed status: {last_status}"

    try:
        kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)
        raise AssertionError("DeleteTable on an already-deleted table did not raise")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on the dead table, got {code}"
        message = exc.response["Error"].get("Message")
        expected_message = f"unconfigured table {tbl_name}"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tables = kc.list_tables(keyspaceName=ks_name)["tables"]
    names = [t["tableName"] for t in tables]
    assert tbl_name not in names, f"deleted table {tbl_name} still present in ListTables: {names}"


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
