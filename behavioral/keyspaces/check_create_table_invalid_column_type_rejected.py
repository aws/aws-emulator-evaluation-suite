"""create-table-invalid-column-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-table-invalid-column-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["keyspaces"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable with a column type that is not a CQL primitive fails with ResourceNotFoundException "UDT
    <type> does not exist"; GetTable then fails "unconfigured table <name>", and only the valid table is
    listed and ACTIVE."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    bad_tbl = _kname(ctx, "sim2real_behav_bad")
    good_tbl = _kname(ctx, "sim2real_behav_good")

    kc.create_keyspace(keyspaceName=ks_name)
    ctx.on_cleanup(lambda: _delete_keyspace_eventually(kc, ks_name))

    # establish keyspace readiness first with a real table, so any error on the bad schema below
    # is unambiguously about the bad schema and not a keyspace-just-created race
    good_schema = {"allColumns": [{"name": "pk", "type": "text"}], "partitionKeys": [{"name": "pk"}]}
    _create_table_when_ready(ctx, kc, ks_name, good_tbl, good_schema)
    _wait_table_status(ctx, kc, ks_name, good_tbl, "ACTIVE", timeout_s=180.0)

    bad_schema = {
        "allColumns": [{"name": "pk", "type": "text"}, {"name": "val", "type": "not_a_real_cql_type"}],
        "partitionKeys": [{"name": "pk"}],
    }
    code, message = _error(lambda: kc.create_table(keyspaceName=ks_name, tableName=bad_tbl, schemaDefinition=bad_schema))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = "UDT not_a_real_cql_type does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the malformed table must not exist
    got, message = _error(lambda: kc.get_table(keyspaceName=ks_name, tableName=bad_tbl))
    assert got == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {got!r}"
    expected_message = f"unconfigured table {bad_tbl}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tables = [t["tableName"] for t in kc.list_tables(keyspaceName=ks_name)["tables"]]
    assert bad_tbl not in tables, f"malformed table {bad_tbl!r} must not appear in list_tables, saw {tables!r}"

    # positive control: the well-formed table (created above) is genuinely there and ACTIVE
    assert good_tbl in tables, f"expected {good_tbl!r} in list_tables, saw {tables!r}"
    good_status = kc.get_table(keyspaceName=ks_name, tableName=good_tbl)["status"]
    assert good_status == "ACTIVE", f"expected good_tbl ACTIVE, got {good_status!r}"


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_keyspace_eventually(kc, ks_name: str, timeout_s: float = 45.0) -> None:
    """DeleteKeyspace cascades to its tables but answers ConflictException while one of them is
    still being created or deleted; retry only that condition, and tolerate not-found."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.delete_keyspace(keyspaceName=ks_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


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
