"""scheduled-action-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-lifecycle"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutScheduledAction creates an action DescribeScheduledActions shows with the exact schedule
    and target action, DeleteScheduledAction removes it, and a second delete is rejected."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    action_name = ctx.unique_name("sim2real-behav-action-")

    target_arn = aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=10,
    )["ScalableTargetARN"]
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
        Schedule="at(2099-06-15T10:00:00)",
        ScalableTargetAction={"MinCapacity": 3, "MaxCapacity": 15},
    )

    actions = aas.describe_scheduled_actions(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScheduledActions"]
    assert len(actions) == 1, f"expected exactly 1 scheduled action, found {len(actions)}: {actions}"
    action = actions[0]
    assert action["ScheduledActionName"] == action_name, (
        f'expected ScheduledActionName {action_name!r}, got {action["ScheduledActionName"]!r}'
    )
    assert action["Schedule"] == "at(2099-06-15T10:00:00)", (
        f'expected Schedule "at(2099-06-15T10:00:00)", got {action["Schedule"]!r}'
    )
    assert action["ScalableTargetAction"] == {"MinCapacity": 3, "MaxCapacity": 15}, (
        f'expected ScalableTargetAction {{"MinCapacity": 3, "MaxCapacity": 15}}, got '
        f'{action["ScalableTargetAction"]!r}'
    )

    aas.delete_scheduled_action(
        ServiceNamespace="dynamodb",
        ScheduledActionName=action_name,
        ResourceId=resource_id,
        ScalableDimension=dimension,
    )
    actions = aas.describe_scheduled_actions(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScheduledActions"]
    assert actions == [], f"expected no scheduled actions after delete, found {actions}"

    # The deleted action is not just absent from the list, it is unusable: deleting the
    # identical, now-dead name again must fail rather than silently succeed a second time.
    error = _client_error(
        lambda: aas.delete_scheduled_action(
            ServiceNamespace="dynamodb",
            ScheduledActionName=action_name,
            ResourceId=resource_id,
            ScalableDimension=dimension,
        )
    )
    code = error.get("Code")
    assert code == "ObjectNotFoundException", (
        f'expected a second delete of the already-deleted action {action_name!r} to raise '
        f'ObjectNotFoundException, got {code!r}'
    )
    # The message names the scalable target by the UUID whose 32 hex digits end its ARN.
    target_hex = target_arn.rsplit("/", 1)[1][-32:]
    target_id = "-".join(
        (target_hex[:8], target_hex[8:12], target_hex[12:16], target_hex[16:20], target_hex[20:])
    )
    assert error.get("Message") == (
        f"No scheduled action found for service namespace: dynamodb, scalable target ID: {target_id}, "
        f"scheduled action name: {action_name}"
    ), (
        f"unexpected rejection message: {error.get('Message')!r}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
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
