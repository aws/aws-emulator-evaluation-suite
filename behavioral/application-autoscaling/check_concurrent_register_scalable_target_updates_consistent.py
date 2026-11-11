"""concurrent-register-scalable-target-updates-consistent."""
from __future__ import annotations

import concurrent.futures
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-register-scalable-target-updates-consistent"
GROUP = "concurrency"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Ten concurrent RegisterScalableTarget upserts on one target, retried on
    ConcurrentUpdateException, leave exactly one target whose MaxCapacity is a submitted value."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    submitted_values = list(range(2, 12))  # 2..11

    # AWS serializes updates per target, so collisions are the common case; the retry is
    # bounded by wall clock rather than attempt count.
    def racer(max_capacity: int) -> tuple[int, int]:
        deadline = time.monotonic() + 60.0
        attempt = 0
        while True:
            try:
                aas.register_scalable_target(
                    ServiceNamespace="dynamodb",
                    ResourceId=resource_id,
                    ScalableDimension=dimension,
                    MinCapacity=1,
                    MaxCapacity=max_capacity,
                )
                return max_capacity, attempt
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ConcurrentUpdateException":
                    raise
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        f"MaxCapacity={max_capacity} racer exhausted its 60s "
                        "ConcurrentUpdateException retry budget without landing"
                    ) from exc
                attempt += 1
                time.sleep(min(2.0, 0.2 * (2**attempt)) + random.uniform(0, 0.3))

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(submitted_values)) as pool:
        results = list(pool.map(racer, submitted_values))

    ctx.on_cleanup(lambda: _deregister_target(aas, resource_id, dimension))

    collided = [value for value, attempt in results if attempt > 0]

    targets = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert len(targets) == 1, (
        f"concurrent upserts produced {len(targets)} targets instead of 1 "
        f"({len(collided)} racers hit ConcurrentUpdateException)"
    )
    # RegisterScalableTarget rejects Tags once the target exists, and no racer knows it creates
    # it, so tagging happens once after the race.
    aas.tag_resource(ResourceARN=targets[0]["ScalableTargetARN"], Tags={"sim2real": CHECK})
    assert targets[0]["MaxCapacity"] in submitted_values, targets[0]["MaxCapacity"]


def _deregister_target(aas, resource_id: str, dimension: str) -> None:
    """Teardown: retry while an update from the race is still pending; raise at the deadline."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            aas.deregister_scalable_target(
                ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ObjectNotFoundException":
                return
            if code != "ConcurrentUpdateException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_provisioned_table(ctx, read_cap: int = 5, write_cap: int = 5) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-aas-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": read_cap, "WriteCapacityUnits": write_cap},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
