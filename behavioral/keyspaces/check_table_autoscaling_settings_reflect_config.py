"""table-autoscaling-settings-reflect-config."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "table-autoscaling-settings-reflect-config"
GROUP = "control-plane-depth"
SERVICES = ["keyspaces"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableAutoScalingSettings returns the min/max/target values configured at CreateTable time."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    schema = {"allColumns": [{"name": "pk", "type": "text"}], "partitionKeys": [{"name": "pk"}]}
    autoscaling = {
        "writeCapacityAutoScaling": {
            "autoScalingDisabled": False,
            "minimumUnits": 5,
            "maximumUnits": 50,
            "scalingPolicy": {"targetTrackingScalingPolicyConfiguration": {"targetValue": 60.0}},
        },
        "readCapacityAutoScaling": {
            "autoScalingDisabled": False,
            "minimumUnits": 5,
            "maximumUnits": 50,
            "scalingPolicy": {"targetTrackingScalingPolicyConfiguration": {"targetValue": 60.0}},
        },
    }
    _create_table_when_ready(
        ctx, kc, ks_name, tbl_name, schema,
        capacitySpecification={"throughputMode": "PROVISIONED", "readCapacityUnits": 5, "writeCapacityUnits": 5},
        autoScalingSpecification=autoscaling,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)))
    _wait_table_status(ctx, kc, ks_name, tbl_name, "ACTIVE", timeout_s=180.0)

    settings = kc.get_table_auto_scaling_settings(keyspaceName=ks_name, tableName=tbl_name)
    write = settings["autoScalingSpecification"]["writeCapacityAutoScaling"]
    read = settings["autoScalingSpecification"]["readCapacityAutoScaling"]
    assert write["minimumUnits"] == 5 and write["maximumUnits"] == 50, write
    assert read["minimumUnits"] == 5 and read["maximumUnits"] == 50, read
    assert write["autoScalingDisabled"] is False, write
    assert read["autoScalingDisabled"] is False, read
    write_target = write["scalingPolicy"]["targetTrackingScalingPolicyConfiguration"]["targetValue"]
    read_target = read["scalingPolicy"]["targetTrackingScalingPolicyConfiguration"]["targetValue"]
    assert write_target == 60.0, write_target
    assert read_target == 60.0, read_target


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
