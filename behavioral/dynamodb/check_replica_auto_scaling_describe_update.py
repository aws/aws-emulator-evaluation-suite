"""replica-auto-scaling-describe-update."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replica-auto-scaling-describe-update"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a replica is added via UpdateTable, DescribeTableReplicaAutoScaling reports both
    regions, and an UpdateTableReplicaAutoScaling write policy is reflected with its min/max units.
    """
    ddb = ctx.client("dynamodb")
    primary_region = ctx.region
    # A global-table replica needs a second, distinct region.
    second_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"
    table_name = ctx.unique_name("sim2real-behav-rtas-")
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
    _wait_table_active(ddb, table_name)
    _enable_write_autoscaling(ctx, table_name)

    try:
        ddb.update_table(
            TableName=table_name,
            ReplicaUpdates=[{"Create": {"RegionName": second_region}}],
        )
    except ClientError as err:
        # Replica provisioning runs as AWSServiceRoleForDynamoDBReplication; a permission
        # boundary denying that role surfaces as AccessDeniedException.
        if err.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                f"account denies the AWSServiceRoleForDynamoDBReplication service-linked "
                f"role the permissions it needs to provision a global-table replica: {err}"
            )
        raise
    ctx.on_cleanup(lambda: _remove_replica_then_delete(ddb, table_name, second_region))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"].get("Replicas", []),
        lambda replicas: len(replicas) == 1 and replicas[0]["ReplicaStatus"] == "ACTIVE",
        timeout_s=900,
        interval_s=15,
    )


    before = ddb.describe_table_replica_auto_scaling(TableName=table_name)["TableAutoScalingDescription"]
    assert before["TableStatus"] == "ACTIVE"
    regions = {r["RegionName"] for r in before["Replicas"]}
    assert regions == {primary_region, second_region}, f"expected both replica regions, got {regions}"

    policy_name = ctx.unique_name("sim2real-behav-rtas-policy-")
    try:
        ddb.update_table_replica_auto_scaling(
            TableName=table_name,
            ProvisionedWriteCapacityAutoScalingUpdate={
                "MinimumUnits": 5,
                "MaximumUnits": 20,
                "ScalingPolicyUpdate": {
                    "PolicyName": policy_name,
                    "TargetTrackingScalingPolicyConfiguration": {"TargetValue": 70.0},
                },
            },
        )
    except ClientError as err:
        raise AssertionError(f"account/region cannot provision application-autoscaling policy: {err}")

    updated = _poll_until(
        lambda: next(
            (
                r.get("ReplicaProvisionedWriteCapacityAutoScalingSettings")
                for r in ddb.describe_table_replica_auto_scaling(TableName=table_name)["TableAutoScalingDescription"][
                    "Replicas"
                ]
                if r["RegionName"] == primary_region
            ),
            None,
        ),
        lambda s: s is not None and s.get("MaximumUnits") == 20,
        timeout_s=120,
        interval_s=5,
    )
    assert updated["MinimumUnits"] == 5
    assert updated["MaximumUnits"] == 20
    assert updated["ScalingPolicies"][0]["PolicyName"] == policy_name
    assert updated["ScalingPolicies"][0]["TargetTrackingScalingPolicyConfiguration"]["TargetValue"] == 70.0


def _enable_write_autoscaling(ctx, table_name: str, *, min_units: int = 5, max_units: int = 10) -> None:
    # UpdateTable rejects ReplicaUpdates Create on a PROVISIONED table unless its write capacity
    # is auto-scaled ("Table write capacity should either be Pay-Per-Request or AutoScaled").
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

