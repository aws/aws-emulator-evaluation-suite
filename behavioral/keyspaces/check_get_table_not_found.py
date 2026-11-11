"""get-table-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-table-not-found"
GROUP = "error-semantics"
SERVICES = ["keyspaces"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTable for a table that was never created inside an existing keyspace returns
    ResourceNotFoundException, while GetTable on a real sibling table in the same keyspace
    still succeeds — isolating the missing-table case from GetTable failing wholesale."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    real_tbl = _kname(ctx, "sim2real_behav_real_tbl")
    missing_tbl = _kname(ctx, "sim2real_behav_missing_tbl")

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": ks_name}])
    ctx.on_cleanup(lambda: _delete_keyspace_eventually(kc, ks_name))

    schema = {"allColumns": [{"name": "pk", "type": "text"}], "partitionKeys": [{"name": "pk"}]}
    _create_table_when_ready(
        ctx, kc, ks_name, real_tbl, schema,
        tags=[{"key": "sim2real", "value": real_tbl}],
    )
    _wait_table_active(ctx, kc, ks_name, real_tbl)

    # Positive control: GetTable resolves a table that genuinely exists.
    control = kc.get_table(keyspaceName=ks_name, tableName=real_tbl)
    assert control["tableName"] == real_tbl, control

    code, message = _error(lambda: kc.get_table(keyspaceName=ks_name, tableName=missing_tbl))
    assert code == "ResourceNotFoundException", code
    expected_message = f"unconfigured table {missing_tbl}"
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


def _wait_table_active(ctx, kc, ks_name: str, tbl_name: str, timeout_s: float = 180.0) -> None:
    """The table must be ACTIVE, not just visible, so the keyspace teardown is not refused."""
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
        if status == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(f"table never reached ACTIVE, last status {status}")


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
