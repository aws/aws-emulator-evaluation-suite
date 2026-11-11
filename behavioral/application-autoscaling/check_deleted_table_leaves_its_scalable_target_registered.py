"""deleted-table-leaves-its-scalable-target-registered."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-table-leaves-its-scalable-target-registered"
GROUP = "scalable-targets"
SERVICES = ["application-autoscaling"]

_NS = "dynamodb"
_DIM = "dynamodb:table:ReadCapacityUnits"
_OTHER = "dynamodb:table:WriteCapacityUnits"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Deleting a DynamoDB table leaves its scalable target registered with its ARN and bounds; a new
    registration against the deleted table is refused, and the orphan can still be deregistered.
    """
    aas = ctx.client("application-autoscaling")
    ddb = ctx.client("dynamodb")
    table = _table(ctx)
    resource_id = f"table/{table}"
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=5)
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                               ScalableDimension=_DIM),
        "ObjectNotFoundException"))
    before = _target(aas, resource_id, _DIM)
    assert before is not None, "the target was not registered"

    ddb.delete_table(TableName=table)
    ddb.get_waiter("table_not_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    orphan = _target(aas, resource_id, _DIM)
    assert orphan is not None, (
        "deleting the table through the API deregistered its scalable target; real AWS leaves it"
    )
    assert orphan["ScalableTargetARN"] == before["ScalableTargetARN"], (
        "the orphaned target changed identity"
    )
    assert (orphan["MinCapacity"], orphan["MaxCapacity"]) == (1, 5), (
        f"the orphaned target's bounds became ({orphan['MinCapacity']}, {orphan['MaxCapacity']})"
    )

    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                               ScalableDimension=_OTHER),
        "ObjectNotFoundException"))
    code, message = _error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_OTHER,
        MinCapacity=1, MaxCapacity=5))
    assert (code, message) == ("ValidationException",
                               f"DynamoDB table does not exist: {resource_id}"), (
        f"registering against the deleted table gave {code!r}: {message!r}"
    )
    assert _target(aas, resource_id, _OTHER) is None, (
        "the refused registration against the deleted table exists anyway"
    )

    aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                   ScalableDimension=_DIM)
    assert _target(aas, resource_id, _DIM) is None, (
        "the orphaned target is still described after its deregistration"
    )


def _target(aas, resource_id, dim):
    found = []
    for page in aas.get_paginator("describe_scalable_targets").paginate(
            ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=dim):
        found.extend(page["ScalableTargets"])
    assert len(found) <= 1, f"{len(found)} targets share one resource id and dimension"
    return found[0] if found else None


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _ignore_missing(fn, *codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-aas-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _ignore_missing(lambda: ddb.delete_table(TableName=name),
                                           "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
