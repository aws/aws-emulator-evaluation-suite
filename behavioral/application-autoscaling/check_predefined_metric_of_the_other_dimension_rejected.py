"""predefined-metric-of-the-other-dimension-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "predefined-metric-of-the-other-dimension-rejected"
GROUP = "scaling-policies"
SERVICES = ["application-autoscaling"]

_DIM = "dynamodb:table:ReadCapacityUnits"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A target-tracking policy on a table's READ dimension that names the WRITE utilization metric
    is refused with a message listing the one metric the dimension supports, nothing is stored, and
    the matching metric is accepted on the same target.
    """
    aas = ctx.client("application-autoscaling")
    table = _create_table(ctx)
    resource_id = f"table/{table}"
    policy = ctx.unique_name("sim2real-behav-aas-pm-")
    _register(ctx, aas, resource_id, _DIM, 1, 10)

    code, msg = _error(lambda: aas.put_scaling_policy(
        PolicyName=policy, ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration=_tt(50.0, "DynamoDBWriteCapacityUtilization")))
    assert code == "ValidationException", f"the write metric on the read dimension gave {code!r}"
    assert msg == (f"Scalable dimension {_DIM} only supports the following predefined metric types: "
                   f"DynamoDBReadCapacityUtilization"), f"rejection message was {msg!r}"
    assert _policies(aas, resource_id) == [], "a policy was stored despite the mismatched metric"

    aas.put_scaling_policy(
        PolicyName=policy, ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration=_tt(50.0, "DynamoDBReadCapacityUtilization"))
    stored = _policies(aas, resource_id)
    assert [(p["PolicyName"], p["TargetTrackingScalingPolicyConfiguration"]
             ["PredefinedMetricSpecification"]["PredefinedMetricType"]) for p in stored] == [
        (policy, "DynamoDBReadCapacityUtilization")], f"stored policies were {stored!r}"


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
