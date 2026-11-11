"""update-table-capacity-mode-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-table-capacity-mode-transition"
GROUP = "control-plane-depth"
SERVICES = ["keyspaces"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTable switches capacitySpecification.throughputMode from PAY_PER_REQUEST to PROVISIONED."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": ks_name}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    schema = {"allColumns": [{"name": "pk", "type": "text"}], "partitionKeys": [{"name": "pk"}]}
    _create_table_when_ready(
        ctx, kc, ks_name, tbl_name, schema,
        capacitySpecification={"throughputMode": "PAY_PER_REQUEST"},
        tags=[{"key": "sim2real", "value": tbl_name}],
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)))
    _wait_table_status(ctx, kc, ks_name, tbl_name, "ACTIVE", timeout_s=180.0)

    before = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)["capacitySpecification"]
    assert before["throughputMode"] == "PAY_PER_REQUEST", before

    kc.update_table(
        keyspaceName=ks_name,
        tableName=tbl_name,
        capacitySpecification={"throughputMode": "PROVISIONED", "readCapacityUnits": 3, "writeCapacityUnits": 3},
    )

    deadline = time.monotonic() + 180.0
    after = None
    while time.monotonic() < deadline:
        after = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)["capacitySpecification"]
        if after["throughputMode"] == "PROVISIONED":
            break
        time.sleep(3.0)
    assert after is not None and after["throughputMode"] == "PROVISIONED", after
    assert after["readCapacityUnits"] == 3 and after["writeCapacityUnits"] == 3, after


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
