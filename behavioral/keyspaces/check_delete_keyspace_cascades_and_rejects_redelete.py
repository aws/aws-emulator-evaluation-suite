"""delete-keyspace-cascades-and-rejects-redelete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-keyspace-cascades-and-rejects-redelete"
GROUP = "overly-permissive"
SERVICES = ["keyspaces"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteKeyspace on a non-empty keyspace cascades to remove its tables too (not blocked by
    ConflictException, per AWS docs: 'deletes a keyspace and all of its tables'); a second
    DeleteKeyspace issued immediately after must not silently succeed on an already-gone keyspace."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": CHECK}])
    keyspace_cleaned = {"done": False}
    ctx.on_cleanup(lambda: None if keyspace_cleaned["done"] else _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    schema = {"allColumns": [{"name": "pk", "type": "text"}], "partitionKeys": [{"name": "pk"}]}
    _create_table_when_ready(ctx, kc, ks_name, tbl_name, schema, tags=[{"key": "sim2real", "value": CHECK}])
    _wait_table_status(ctx, kc, ks_name, tbl_name, "ACTIVE", timeout_s=180.0)

    # DeleteKeyspace on the non-empty keyspace must be accepted (cascade delete), not rejected.
    kc.delete_keyspace(keyspaceName=ks_name)

    # effect present: both the table and the keyspace eventually disappear as a result of the cascade
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 240.0
    table_gone = False
    keyspace_gone = False
    while time.monotonic() < deadline and not (table_gone and keyspace_gone):
        if not table_gone:
            try:
                kc.get_table(keyspaceName=ks_name, tableName=tbl_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    table_gone = True
                else:
                    raise
        if not keyspace_gone:
            try:
                kc.get_keyspace(keyspaceName=ks_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    keyspace_gone = True
                else:
                    raise
        if not (table_gone and keyspace_gone):
            time.sleep(3.0)
    assert table_gone, "table was never removed by the DeleteKeyspace cascade"
    assert keyspace_gone, "keyspace was never fully removed"
    keyspace_cleaned["done"] = True

    # overly-permissive boundary: re-deleting the now-gone keyspace must not silently succeed
    code, message = _error(lambda: kc.delete_keyspace(keyspaceName=ks_name))
    assert code == "ResourceNotFoundException", code
    expected_message = f"Cannot drop non existing keyspace '{ks_name}'"
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

