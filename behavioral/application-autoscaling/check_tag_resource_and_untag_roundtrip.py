"""tag-resource-and-untag-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-untag-roundtrip"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges new tags onto a scalable target, editing an existing key's
    value in place, and UntagResource removes exactly the requested keys."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    target_arn = aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=5,
    )["ScalableTargetARN"]
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )

    aas.tag_resource(ResourceARN=target_arn, Tags={"env": "staging", "owner": "sim2real"})
    tags = aas.list_tags_for_resource(ResourceARN=target_arn)["Tags"]
    assert tags == {"env": "staging", "owner": "sim2real"}, tags

    # Re-tagging an existing key replaces its value; a new key is merged in.
    aas.tag_resource(ResourceARN=target_arn, Tags={"env": "prod", "team": "aas"})
    tags = aas.list_tags_for_resource(ResourceARN=target_arn)["Tags"]
    assert tags == {"env": "prod", "owner": "sim2real", "team": "aas"}, tags

    aas.untag_resource(ResourceARN=target_arn, TagKeys=["owner"])
    tags = aas.list_tags_for_resource(ResourceARN=target_arn)["Tags"]
    assert tags == {"env": "prod", "team": "aas"}, tags


def _create_provisioned_table(ctx, read_cap: int = 5, write_cap: int = 5) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-aas-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": read_cap, "WriteCapacityUnits": write_cap},
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
