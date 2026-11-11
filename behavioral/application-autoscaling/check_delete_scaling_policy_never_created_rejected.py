"""delete-scaling-policy-never-created-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-scaling-policy-never-created-rejected"
GROUP = "scaling-policies"
SERVICES = ["application-autoscaling"]

_DIM = "dynamodb:table:ReadCapacityUnits"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteScalingPolicy for a never-put name on a registered target is refused with
    ObjectNotFoundException naming the full key, the target's real policy and alarms are untouched,
    and deleting the real policy then succeeds and removes it.
    """
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    table = _create_table(ctx)
    resource_id = f"table/{table}"
    real = ctx.unique_name("sim2real-behav-aas-real-")
    ghost = ctx.unique_name("sim2real-behav-aas-ghost-")
    _register(ctx, aas, resource_id, _DIM, 1, 10)
    alarms = [a["AlarmName"] for a in aas.put_scaling_policy(
        PolicyName=real, ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration=_tt(50.0, "DynamoDBReadCapacityUtilization"),
    )["Alarms"]]

    code, msg = _error(lambda: aas.delete_scaling_policy(
        PolicyName=ghost, ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=_DIM))
    assert code == "ObjectNotFoundException", f"deleting a never-created policy gave {code!r}"
    assert msg == (f"No scaling policy found for service namespace: dynamodb, resource ID: "
                   f"{resource_id}, scalable dimension: {_DIM}, policy name: {ghost}"), (
        f"rejection message was {msg!r}"
    )
    assert [p["PolicyName"] for p in _policies(aas, resource_id)] == [real], (
        "the refused delete disturbed the target's real policy"
    )
    live = cw.describe_alarms(AlarmNames=alarms)["MetricAlarms"]
    assert len(live) == len(alarms) == 4, (
        f"{len(live)} of the real policy's {len(alarms)} alarms survive the refused delete"
    )

    aas.delete_scaling_policy(PolicyName=real, ServiceNamespace="dynamodb", ResourceId=resource_id,
                              ScalableDimension=_DIM)
    assert _policies(aas, resource_id) == [], "the real policy survived its own delete"


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
