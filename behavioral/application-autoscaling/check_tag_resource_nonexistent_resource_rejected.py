"""tag-resource-nonexistent-resource-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a well-formed but nonexistent scalable-target ARN is refused with
    ValidationException; tagging a real registered target succeeds and lists back."""
    aas = ctx.client("application-autoscaling")
    bogus_arn = (
        f"arn:aws:application-autoscaling:{ctx.region}:{ctx.account}:"
        "scalable-target/00000000-0000-0000-0000-000000000000"
    )

    # AWS answers a nonexistent target ARN with ValidationException, not ResourceNotFoundException.
    error = _client_error(lambda: aas.tag_resource(ResourceARN=bogus_arn, Tags={"env": "sim2real"}))
    assert error.get("Code") == "ValidationException", error
    assert error.get("Message") == "Access Denied", (
        f"unexpected rejection message: {error.get('Message')!r}"
    )

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

    aas.tag_resource(ResourceARN=target_arn, Tags={"env": "sim2real"})
    tags = aas.list_tags_for_resource(ResourceARN=target_arn)["Tags"]
    assert tags == {"env": "sim2real"}, tags


def _client_error(fn: Any) -> dict[str, Any]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
