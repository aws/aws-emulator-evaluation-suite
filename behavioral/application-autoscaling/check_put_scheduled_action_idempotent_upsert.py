"""put-scheduled-action-idempotent-upsert."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-scheduled-action-idempotent-upsert"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling PutScheduledAction again with the same ScheduledActionName updates the
    existing scheduled action's Schedule in place rather than creating a second one."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    action_name = ctx.unique_name("sim2real-behav-action-")

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=10,
    )
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )

    aas.put_scheduled_action(
        ServiceNamespace="dynamodb",
        ScheduledActionName=action_name,
        ResourceId=resource_id,
        ScalableDimension=dimension,
        Schedule="at(2099-01-01T00:00:00)",
        ScalableTargetAction={"MinCapacity": 2, "MaxCapacity": 10},
    )
    aas.put_scheduled_action(
        ServiceNamespace="dynamodb",
        ScheduledActionName=action_name,
        ResourceId=resource_id,
        ScalableDimension=dimension,
        Schedule="at(2099-12-31T23:59:00)",
        ScalableTargetAction={"MinCapacity": 4, "MaxCapacity": 20},
    )

    actions = aas.describe_scheduled_actions(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScheduledActions"]
    assert len(actions) == 1, f"upsert created a duplicate scheduled action: {actions}"
    assert actions[0]["Schedule"] == "at(2099-12-31T23:59:00)", (
        f"expected the second put's schedule to win, got {actions[0]['Schedule']!r}"
    )
    assert actions[0]["ScalableTargetAction"] == {"MinCapacity": 4, "MaxCapacity": 20}, (
        f"expected the second put's target action to win, got {actions[0]['ScalableTargetAction']!r}"
    )


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
