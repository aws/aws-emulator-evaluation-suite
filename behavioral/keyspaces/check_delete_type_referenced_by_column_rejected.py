"""delete-type-referenced-by-column-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-type-referenced-by-column-rejected"
GROUP = "overly-permissive"
SERVICES = ["keyspaces"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteType on a user-defined type still used as a table column is rejected with ConflictException."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    type_name = _kname(ctx, "sim2real_behav_type")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    _create_type_when_ready(ctx, kc, ks_name, type_name, [{"name": "street", "type": "text"}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_type(keyspaceName=ks_name, typeName=type_name)))
    _wait_type_status(ctx, kc, ks_name, type_name, "ACTIVE", timeout_s=120.0)

    schema = {
        "allColumns": [{"name": "pk", "type": "text"}, {"name": "addr", "type": f"frozen<{type_name}>"}],
        "partitionKeys": [{"name": "pk"}],
    }
    kc.create_table(keyspaceName=ks_name, tableName=tbl_name, schemaDefinition=schema, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)))
    _wait_table_status(ctx, kc, ks_name, tbl_name, "ACTIVE", timeout_s=180.0)

    code, message = _error(lambda: kc.delete_type(keyspaceName=ks_name, typeName=type_name))
    assert code == "ConflictException", code
    expected_message = f"{type_name} is referenced by other UDTs or tables."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the type is still there
    got = kc.get_type(keyspaceName=ks_name, typeName=type_name)
    assert got["status"] == "ACTIVE", got["status"]

    # positive control: once the referencing table is removed, the type can be deleted
    kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 180.0
    table_gone = False
    while time.monotonic() < deadline:
        try:
            kc.get_table(keyspaceName=ks_name, tableName=tbl_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                table_gone = True
                break
            raise
        time.sleep(3.0)
    assert table_gone, "table was never fully removed"

    kc.delete_type(keyspaceName=ks_name, typeName=type_name)

    # deletes prove gone and unusable: an independent read no longer finds the type,
    # and a repeat delete on the now-dead id fails with the same specific not-found code.
    deadline = time.monotonic() + 120.0
    type_gone = False
    while time.monotonic() < deadline:
        try:
            kc.get_type(keyspaceName=ks_name, typeName=type_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                type_gone = True
                break
            raise
        time.sleep(2.0)
    assert type_gone, "type was never fully removed"

    redelete_code, message = _error(lambda: kc.delete_type(keyspaceName=ks_name, typeName=type_name))
    assert redelete_code == "ResourceNotFoundException", redelete_code
    expected_message = f"UDT {type_name} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_type_when_ready(ctx, kc, ks_name: str, type_name: str, fields: list, timeout_s: float = 90.0) -> None:
    """CreateType right after CreateKeyspace can transiently 404 until the keyspace is
    visible; retry only that specific transient condition."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.create_type(keyspaceName=ks_name, typeName=type_name, fieldDefinitions=fields)
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


def _wait_type_status(ctx, kc, ks_name: str, type_name: str, target: str, timeout_s: float = 120.0) -> None:
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = kc.get_type(keyspaceName=ks_name, typeName=type_name)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(2.0)
            continue
        if status == target:
            return
        time.sleep(2.0)
    raise AssertionError(f"type never reached {target}, last status {status}")


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
