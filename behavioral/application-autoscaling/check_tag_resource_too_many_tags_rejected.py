"""tag-resource-too-many-tags-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-too-many-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource past the 50-tag limit is refused with ValidationException and lands no tags; a
    batch under the limit succeeds."""
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

    # The limit surfaces as ValidationException, not the generic TooManyTagsException.
    too_many_tags = {f"sim2real-key-{i}": f"v{i}" for i in range(51)}
    error = _client_error(lambda: aas.tag_resource(ResourceARN=target_arn, Tags=too_many_tags))
    assert error.get("Code") == "ValidationException", error
    assert error.get("Message") == "The resultant tag set must not have more than 50 user tags.", (
        f"unexpected rejection message: {error.get('Message')!r}"
    )

    tags = aas.list_tags_for_resource(ResourceARN=target_arn)["Tags"]
    assert tags == {}, f"tags leaked from a rejected over-limit request: {tags}"

    # Positive control: a batch within the limit succeeds and is visible.
    valid_tags = {f"sim2real-key-{i}": f"v{i}" for i in range(5)}
    aas.tag_resource(ResourceARN=target_arn, Tags=valid_tags)
    tags = aas.list_tags_for_resource(ResourceARN=target_arn)["Tags"]
    assert tags == valid_tags, tags


def _client_error(fn: Any) -> dict[str, Any]:
    """The Error dict ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
