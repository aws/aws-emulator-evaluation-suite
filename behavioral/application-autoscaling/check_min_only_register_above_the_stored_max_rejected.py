"""min-only-register-above-the-stored-max-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "min-only-register-above-the-stored-max-rejected"
GROUP = "scalable-targets"
SERVICES = ["application-autoscaling"]

_DIM = "dynamodb:table:WriteCapacityUnits"


def _bounds(aas, resource_id):
    targets = aas.describe_scalable_targets(ServiceNamespace="dynamodb", ResourceIds=[resource_id],
                                            ScalableDimension=_DIM)["ScalableTargets"]
    assert len(targets) == 1, f"expected one scalable target, got {len(targets)}"
    return targets[0]["MinCapacity"], targets[0]["MaxCapacity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-registering a (1, 7) target with ONLY MinCapacity=9 is refused because the merged result
    puts the minimum above the STORED maximum; the target keeps (1, 7), and a min-only update to 7
    (equal to the stored maximum) is accepted.
    """
    aas = ctx.client("application-autoscaling")
    table = _create_table(ctx)
    resource_id = f"table/{table}"
    _register(ctx, aas, resource_id, _DIM, 1, 7)

    code, msg = _error(lambda: aas.register_scalable_target(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=_DIM, MinCapacity=9))
    assert code == "ValidationException", f"MinCapacity 9 over a stored MaxCapacity 7 gave {code!r}"
    assert msg == "Maximum capacity cannot be less than minimum capacity", f"rejection message was {msg!r}"
    assert _bounds(aas, resource_id) == (1, 7), (
        f"the refused update changed the bounds to {_bounds(aas, resource_id)!r}"
    )

    aas.register_scalable_target(ServiceNamespace="dynamodb", ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=7)
    assert _bounds(aas, resource_id) == (7, 7), (
        f"a min-only update to the stored maximum left {_bounds(aas, resource_id)!r}, expected (7, 7)"
    )


def _error(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _delete_table(ddb, name):
    """Delete the table, tolerating the UPDATING window a capacity change leaves behind."""
    for _ in range(8):
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
            time.sleep(5)
    ddb.delete_table(TableName=name)


def _create_table(ctx, *, index=None):
    """A PROVISIONED 1/1 table (plus an optional 1/1 GSI) that this check owns."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-aas-")
    attrs = [{"AttributeName": "pk", "AttributeType": "S"}]
    kwargs = {}
    if index:
        attrs.append({"AttributeName": "gk", "AttributeType": "S"})
        kwargs["GlobalSecondaryIndexes"] = [{
            "IndexName": index,
            "KeySchema": [{"AttributeName": "gk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "KEYS_ONLY"},
            "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        }]
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=attrs,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
        **kwargs,
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _register(ctx, aas, resource_id, dimension, lo, hi):
    aas.register_scalable_target(ServiceNamespace="dynamodb", ResourceId=resource_id,
                                 ScalableDimension=dimension, MinCapacity=lo, MaxCapacity=hi)

    def _deregister():
        try:
            aas.deregister_scalable_target(ServiceNamespace="dynamodb", ResourceId=resource_id,
                                           ScalableDimension=dimension)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ObjectNotFoundException":
                raise
    ctx.on_cleanup(_deregister)


def _policies(aas, resource_id, dimension=None):
    kwargs = {"ServiceNamespace": "dynamodb", "ResourceId": resource_id}
    if dimension:
        kwargs["ScalableDimension"] = dimension
    out = []
    for page in aas.get_paginator("describe_scaling_policies").paginate(**kwargs):
        out.extend(page["ScalingPolicies"])
    return out


def _tt(value, metric):
    return {"TargetValue": value, "PredefinedMetricSpecification": {"PredefinedMetricType": metric}}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
