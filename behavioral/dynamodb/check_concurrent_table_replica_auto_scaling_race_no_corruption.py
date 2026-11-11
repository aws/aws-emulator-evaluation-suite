"""concurrent-table-replica-auto-scaling-race-no-corruption."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-table-replica-auto-scaling-race-no-corruption"
GROUP = "concurrency"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateTableReplicaAutoScaling calls setting different read-capacity
    (Minimum, Maximum) pairs on one replica serialize: the final settings are exactly one racer's
    pair, never a hybrid, and the AutoScalingRoleArn stays bound."""
    start = time.monotonic()

    # The whole check has a 300s wall-clock budget; later polls get what remains of it so a
    # slow wait ends in a clean assertion rather than a hard kill.
    def _remaining_budget(total: float = 270.0, floor: float = 20.0) -> float:
        return max(floor, total - (time.monotonic() - start))

    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    aas = ctx.client("application-autoscaling")

    # DynamoDB can take over 200s to trust a freshly created custom role; the service-linked
    # AWSServiceRoleForApplicationAutoScaling_DynamoDBTable role is trusted immediately.
    role_arn = _get_or_create_service_linked_role(iam)

    table_name = ctx.unique_name("sim2real-behav-trasr-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=1,
        ctx=ctx,
    )

    # Adding a replica to a fixed PROVISIONED table fails with "Table write capacity should
    # either be Pay-Per-Request or AutoScaled.", so write capacity is put under auto scaling first.
    write_scaling_resource_id = f"table/{table_name}"
    _register_scalable_target_with_retry(
        aas, write_scaling_resource_id, role_arn, timeout_s=60, interval_s=1, ctx=ctx
    )
    ctx.on_cleanup(
        lambda: _safe_deregister_scalable_target(aas, write_scaling_resource_id)
    )
    _put_write_scaling_policy_with_retry(
        aas,
        write_scaling_resource_id,
        ctx.unique_name("sim2real-behav-trasr-write-"),
        timeout_s=60,
        interval_s=1,
        ctx=ctx,
    )

    region2 = _secondary_region(ctx.region)
    _create_replica_with_retry(ddb, table_name, region2, interval_s=1, ctx=ctx)
    ctx.on_cleanup(lambda: _safe_remove_replica(ddb, table_name, region2))
    # Bounded by the remaining budget, reserving time for the downstream steps.
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == region2 and r["ReplicaStatus"] == "ACTIVE"
            for r in table.get("Replicas", [])
        ),
        timeout_s=min(190, _remaining_budget(total=190, floor=30)),
        interval_s=1,
        ctx=ctx,
    )
    _poll_until(
        lambda: ddb.describe_table_replica_auto_scaling(TableName=table_name)[
            "TableAutoScalingDescription"
        ],
        lambda desc: desc["TableStatus"] == "ACTIVE",
        timeout_s=min(120, _remaining_budget()),
        interval_s=1,
        ctx=ctx,
    )

    def _attempt(config: dict[str, Any]) -> dict[str, Any] | None:
        try:
            # The per-replica knob this API exposes is read capacity; v2 global-table write
            # capacity is configured through Application Auto Scaling.
            return ddb.update_table_replica_auto_scaling(
                TableName=table_name,
                ReplicaUpdates=[
                    {
                        "RegionName": ctx.region,
                        "ReplicaProvisionedReadCapacityAutoScalingUpdate": {
                            "MinimumUnits": config["min"],
                            "MaximumUnits": config["max"],
                            "AutoScalingRoleArn": role_arn,
                            "ScalingPolicyUpdate": {
                                "PolicyName": config["policy_name"],
                                # The "Update" shape takes no PredefinedMetricSpecification;
                                # the read-utilization metric is implicit.
                                "TargetTrackingScalingPolicyConfiguration": {
                                    "TargetValue": 55.0,
                                    "ScaleInCooldown": 60,
                                    "ScaleOutCooldown": 60,
                                },
                            },
                        },
                    }
                ],
            )
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc)
            if code in ("ValidationException", "AccessDeniedException"):
                return None  # scalable-target/alarm creation for this replica not settled yet
            if code == "ResourceInUseException":
                return {"_conflict": True}
            raise

    # The first enable is slow (DynamoDB registers a scalable target and creates alarms), so a
    # baseline policy, distinct from both racers' pairs, is applied sequentially first; the race
    # is then an update of an established policy.

    baseline_config = {
        "min": 5,
        "max": 10,
        "policy_name": ctx.unique_name("sim2real-behav-trasr-baseline-"),
    }

    def _read_capacity_settings(expected_max: float | None = None) -> dict[str, Any] | None:
        desc = ddb.describe_table_replica_auto_scaling(TableName=table_name)[
            "TableAutoScalingDescription"
        ]
        for replica in desc["Replicas"]:
            if replica["RegionName"] == ctx.region:
                settings = replica.get("ReplicaProvisionedReadCapacityAutoScalingSettings")
                if settings and (expected_max is None or settings.get("MaximumUnits") == expected_max):
                    return settings
        return None

    def _attempt_baseline() -> dict[str, Any] | None:
        resp = _attempt(baseline_config)
        if resp is not None and resp.get("_conflict"):
            return None  # nothing else should be racing yet, but tolerate a transient conflict
        return resp

    # Reserve part of the remaining budget for the race and final-settings check.
    _poll_until(
        _attempt_baseline,
        lambda r: r is not None,
        timeout_s=max(30.0, _remaining_budget() - 40.0),
        interval_s=1,
        ctx=ctx,
    )
    _poll_until(
        lambda: _read_capacity_settings(baseline_config["max"]),
        lambda s: s is not None,
        timeout_s=max(20.0, _remaining_budget() - 20.0),
        interval_s=1,
        ctx=ctx,
    )

    config_a = {"min": 5, "max": 15, "policy_name": ctx.unique_name("sim2real-behav-trasr-a-")}
    config_b = {"min": 3, "max": 25, "policy_name": ctx.unique_name("sim2real-behav-trasr-b-")}

    barrier = threading.Barrier(2)
    results: dict[str, dict[str, Any]] = {}

    def _race(name: str, config: dict[str, Any]) -> None:
        barrier.wait()

        def _attempt_with_retry() -> dict[str, Any] | None:
            resp = _attempt(config)
            if resp is not None and resp.get("_conflict"):
                return None  # keep retrying past a serialization conflict
            return resp

        resp = _poll_until(
            _attempt_with_retry, lambda r: r is not None, timeout_s=_remaining_budget(), interval_s=1,
            ctx=ctx,
        )
        results[name] = {"config": config, "response": resp}

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda item: _race(*item), [("A", config_a), ("B", config_b)]))

    assert set(results) == {"A", "B"}, results

    def _final_settings() -> dict[str, Any] | None:
        desc = ddb.describe_table_replica_auto_scaling(TableName=table_name)[
            "TableAutoScalingDescription"
        ]
        for replica in desc["Replicas"]:
            if replica["RegionName"] == ctx.region:
                settings = replica.get("ReplicaProvisionedReadCapacityAutoScalingSettings")
                if settings and settings.get("MaximumUnits") in (config_a["max"], config_b["max"]):
                    return settings
        return None

    settings = _poll_until(
        _final_settings, lambda s: s is not None, timeout_s=_remaining_budget(), interval_s=1,
        ctx=ctx,
    )
    valid_pairs = {
        (config_a["min"], config_a["max"]),
        (config_b["min"], config_b["max"]),
    }
    final_pair = (settings["MinimumUnits"], settings["MaximumUnits"])
    assert final_pair in valid_pairs, (
        f"final (Minimum, Maximum)={final_pair} is neither racer's config {valid_pairs} -- "
        "the scaling policy was corrupted by the concurrent update"
    )
    assert settings["AutoScalingRoleArn"] == role_arn, (
        f"expected AutoScalingRoleArn={role_arn!r} still bound after the race, "
        f"got {settings['AutoScalingRoleArn']!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _secondary_region(primary_region: str) -> str:
    """A region distinct from the primary, for a global table replica."""
    return "us-west-2" if primary_region != "us-west-2" else "us-east-1"


def _create_replica_with_retry(
    ddb: Any, table_name: str, region: str, *, timeout_s: float = 90, interval_s: float = 1,
    ctx: Any,
) -> None:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": region}}])
            return
        except Exception as exc:  # noqa: BLE001
            transient = _error_code_from_exc(exc) == "AccessDeniedException" and "security token" in str(
                exc
            ).lower()
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError(f"replica {region} created: the run budget ended first; not graded") from None
                raise
            time.sleep(interval_s)


def _safe_remove_replica(ddb: Any, table_name: str, region: str) -> None:
    try:
        ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": region}}])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise
        return
    # DeleteTable is refused while the source table still lists the replica, so wait until the
    # replica is gone and the table is ACTIVE again.
    deadline = time.monotonic() + 840.0
    while True:
        try:
            table = ddb.describe_table(TableName=table_name)["Table"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if table["TableStatus"] == "ACTIVE" and not any(
            r.get("RegionName") == region for r in table.get("Replicas", [])
        ):
            return
        assert time.monotonic() < deadline, (
            f"replica {region} of {table_name} still listed 840 s after its removal: "
            f"{table.get('Replicas')!r}"
        )
        time.sleep(2.0)


def _safe_deregister_scalable_target(aas: Any, resource_id: str) -> None:
    try:
        aas.deregister_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension="dynamodb:table:WriteCapacityUnits",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ObjectNotFoundException":
            raise


def _register_scalable_target_with_retry(
    aas: Any,
    resource_id: str,
    role_arn: str,
    *,
    timeout_s: float = 60,
    interval_s: float = 1,
    ctx: Any,
) -> None:
    # A just-created service-linked role can briefly draw ValidationException or
    # AccessDeniedException on the first Application Auto Scaling call.
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            aas.register_scalable_target(
                ServiceNamespace="dynamodb",
                ResourceId=resource_id,
                ScalableDimension="dynamodb:table:WriteCapacityUnits",
                MinCapacity=5,
                MaxCapacity=20,
                RoleARN=role_arn,
                Tags={"sim2real": CHECK},
            )
            return
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc)
            transient = code in ("ValidationException", "AccessDeniedException")
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError(f"scalable target {resource_id} registered: the run budget ended first; not graded") from None
                raise
            time.sleep(interval_s)


def _put_write_scaling_policy_with_retry(
    aas: Any,
    resource_id: str,
    policy_name: str,
    *,
    timeout_s: float = 60,
    interval_s: float = 1,
    ctx: Any,
) -> None:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            aas.put_scaling_policy(
                PolicyName=policy_name,
                ServiceNamespace="dynamodb",
                ResourceId=resource_id,
                ScalableDimension="dynamodb:table:WriteCapacityUnits",
                PolicyType="TargetTrackingScaling",
                TargetTrackingScalingPolicyConfiguration={
                    "TargetValue": 55.0,
                    "PredefinedMetricSpecification": {
                        "PredefinedMetricType": "DynamoDBWriteCapacityUtilization"
                    },
                },
            )
            return
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc)
            transient = code in ("ValidationException", "AccessDeniedException")
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError(f"scaling policy {policy_name} put: the run budget ended first; not graded") from None
                raise
            time.sleep(interval_s)


def _get_or_create_service_linked_role(iam: Any) -> str:
    # Account-wide service-linked role, deliberately not torn down: other tables in the
    # account may depend on it.
    role_name = "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable"
    try:
        return iam.get_role(RoleName=role_name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        pass
    try:
        return iam.create_service_linked_role(
            AWSServiceName="dynamodb.application-autoscaling.amazonaws.com"
        )["Role"]["Arn"]
    except Exception as exc:  # noqa: BLE001
        # A concurrent creator may have just created it.
        if _error_code_from_exc(exc) == "InvalidInput":
            return iam.get_role(RoleName=role_name)["Role"]["Arn"]
        raise


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
    ctx: Any,
) -> Any:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s:.0f}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
