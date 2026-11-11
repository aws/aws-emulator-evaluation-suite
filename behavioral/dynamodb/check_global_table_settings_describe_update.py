"""global-table-settings-describe-update."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-table-settings-describe-update"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeGlobalTableSettings and UpdateGlobalTableSettings raise GlobalTableNotFoundException with the exact
    message for an ACTIVE two-region table made global with UpdateTable ReplicaUpdates, and the rejected
    update leaves the table's read capacity at 5.
    """
    ddb = ctx.client("dynamodb")
    primary_region = ctx.region
    second_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"
    table_name = ctx.unique_name("sim2real-behav-gts-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, table_name))
    _wait_table_active(ddb, table_name, timeout_s=60)
    _enable_write_autoscaling(ctx, table_name)

    try:
        ddb.update_table(
            TableName=table_name,
            ReplicaUpdates=[{"Create": {"RegionName": second_region}}],
        )
    except ClientError as err:
        # Real AWS provisions a replica by having the account's
        # AWSServiceRoleForDynamoDBReplication service-linked role call
        # DescribeTable against the source table; an account whose policies
        # deny that role gets an AccessDeniedException naming that
        # service-linked role, and cannot provision global tables.
        if err.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                f"account denies the AWSServiceRoleForDynamoDBReplication service-linked "
                f"role the permissions it needs to provision a global-table replica: {err}"
            )
        raise
    ctx.on_cleanup(lambda: _remove_replica_then_delete(ddb, table_name, second_region))

    # Positive control: the replica-based (2019.11.21) global table is real and working, so the
    # legacy settings API's rejection below is that control plane's own withdrawal -- not this
    # account being broadly denied, and not the table having simply never become global.
    replicas = _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"].get("Replicas", []),
        lambda rs: any(r["RegionName"] == second_region and r.get("ReplicaStatus") == "ACTIVE" for r in rs),
        timeout_s=180,
        interval_s=5,
    )
    assert any(r["RegionName"] == second_region for r in replicas), (
        f"expected an ACTIVE replica for {second_region}, got {replicas}"
    )
    baseline_capacity = ddb.describe_table(TableName=table_name)["Table"]["ProvisionedThroughput"][
        "ReadCapacityUnits"
    ]
    assert baseline_capacity == 5, f"expected the table's own reported read capacity to be 5, got {baseline_capacity}"

    expected_message = f"Global table with name: '{table_name}' does not exist."
    describe_code, describe_message = _error_code_and_message(
        lambda: ddb.describe_global_table_settings(GlobalTableName=table_name)
    )
    assert describe_code == "GlobalTableNotFoundException", (
        f"expected DescribeGlobalTableSettings to reject a real replica-based global table with "
        f"GlobalTableNotFoundException, got {describe_code}"
    )
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    update_code, update_message = _error_code_and_message(
        lambda: ddb.update_global_table_settings(
            GlobalTableName=table_name,
            ReplicaSettingsUpdate=[
                {"RegionName": primary_region, "ReplicaProvisionedReadCapacityUnits": 10}
            ],
        )
    )
    assert update_code == "GlobalTableNotFoundException", (
        f"expected UpdateGlobalTableSettings to reject the same real global table with "
        f"GlobalTableNotFoundException, got {update_code}"
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )

    # An independent read at the destination proving the rejected update had
    # NO side effect -- the table's own reported capacity is unchanged by the attempted update.
    after_capacity = ddb.describe_table(TableName=table_name)["Table"]["ProvisionedThroughput"][
        "ReadCapacityUnits"
    ]
    assert after_capacity == baseline_capacity == 5, (
        f"expected the rejected UpdateGlobalTableSettings call to leave read capacity at "
        f"{baseline_capacity}, got {after_capacity}"
    )


def _enable_write_autoscaling(ctx, table_name: str, *, min_units: int = 5, max_units: int = 10) -> None:
    # A PROVISIONED table must have its write capacity either Pay-Per-Request
    # or auto-scaled before UpdateTable will accept a ReplicaUpdates Create
    # action; register an Application Auto Scaling target + policy for the
    # table's WriteCapacityUnits to satisfy that precondition.
    aas = ctx.client("application-autoscaling")
    resource_id = f"table/{table_name}"
    try:
        aas.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension="dynamodb:table:WriteCapacityUnits",
            MinCapacity=min_units,
            MaxCapacity=max_units,
        )
        aas.put_scaling_policy(
            PolicyName=f"{table_name}-write-scaling",
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension="dynamodb:table:WriteCapacityUnits",
            PolicyType="TargetTrackingScaling",
            TargetTrackingScalingPolicyConfiguration={
                "TargetValue": 70.0,
                "PredefinedMetricSpecification": {
                    "PredefinedMetricType": "DynamoDBWriteCapacityUtilization"
                },
            },
        )
    except ClientError as err:
        raise AssertionError(
            f"account/region cannot provision application-autoscaling for table write capacity: {err}"
        )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _error_code_and_message(fn: Callable[[], Any]) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _wait_table_active(ddb, table_name: str, timeout_s: float = 120) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3,
    )


def _delete_table_ignore(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _remove_replica_then_delete(ddb, table_name: str, second_region: str) -> None:
    # Removing a replica region via UpdateTable also tears down the
    # underlying table AWS auto-provisioned in that region, so only the
    # primary-region table needs an explicit DeleteTable afterwards.
    try:
        ddb.update_table(
            TableName=table_name,
            ReplicaUpdates=[{"Delete": {"RegionName": second_region}}],
        )
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                desc = ddb.describe_table(TableName=table_name)["Table"]
                if all(r["RegionName"] != second_region for r in desc.get("Replicas", [])):
                    break
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ResourceNotFoundException",
                    "TableNotFoundException",
                ):
                    raise
                break
            time.sleep(5)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise
    _delete_table_ignore(ddb, table_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

