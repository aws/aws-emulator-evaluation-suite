"""deregister-index-target-leaves-the-table-policy-and-alarms."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-index-target-leaves-the-table-policy-and-alarms"
GROUP = "scaling-policies"
SERVICES = ["application-autoscaling"]

_TBL_DIM = "dynamodb:table:ReadCapacityUnits"
_IDX_DIM = "dynamodb:index:ReadCapacityUnits"


def _alarm_scopes(cw, names):
    """{alarm name: (metric names..., dimension dict)} for the alarms that still exist."""
    out = {}
    for page in cw.get_paginator("describe_alarms").paginate(AlarmNames=names):
        for a in page["MetricAlarms"]:
            out[a["AlarmName"]] = (a["Namespace"], a["MetricName"],
                                   {d["Name"]: d["Value"] for d in a["Dimensions"]})
    return out


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A GSI policy mints alarms on the INDEX (TableName + GlobalSecondaryIndexName dimensions), a
    base-table policy mints table-only alarms, and deregistering the index target removes only the
    index's policy and alarms -- the table's policy and its four alarms survive.
    """
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    index = "by-gk"
    table = _create_table(ctx, index=index)
    table_id = f"table/{table}"
    index_id = f"table/{table}/index/{index}"
    table_policy = ctx.unique_name("sim2real-behav-aas-tbl-")
    index_policy = ctx.unique_name("sim2real-behav-aas-idx-")

    _register(ctx, aas, table_id, _TBL_DIM, 1, 10)
    _register(ctx, aas, index_id, _IDX_DIM, 1, 10)
    table_put = aas.put_scaling_policy(
        PolicyName=table_policy, ServiceNamespace="dynamodb", ResourceId=table_id,
        ScalableDimension=_TBL_DIM, PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration=_tt(50.0, "DynamoDBReadCapacityUtilization"))
    index_put = aas.put_scaling_policy(
        PolicyName=index_policy, ServiceNamespace="dynamodb", ResourceId=index_id,
        ScalableDimension=_IDX_DIM, PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration=_tt(50.0, "DynamoDBReadCapacityUtilization"))
    table_alarms = [a["AlarmName"] for a in table_put["Alarms"]]
    index_alarms = [a["AlarmName"] for a in index_put["Alarms"]]
    assert len(table_alarms) == 4 and len(index_alarms) == 4, (
        f"expected 4 alarms per DynamoDB target-tracking policy, got {len(table_alarms)} for the "
        f"table and {len(index_alarms)} for the index"
    )

    scopes = _alarm_scopes(cw, table_alarms + index_alarms)
    assert set(scopes) == set(table_alarms + index_alarms), (
        f"{len(scopes)} of the {len(table_alarms) + len(index_alarms)} minted alarms are visible "
        f"in CloudWatch"
    )
    for name in index_alarms:
        ns, metric, dims = scopes[name]
        assert ns == "AWS/DynamoDB" and metric in ("ConsumedReadCapacityUnits",
                                                   "ProvisionedReadCapacityUnits"), (
            f"index alarm watches {ns}/{metric}"
        )
        assert dims == {"TableName": table, "GlobalSecondaryIndexName": index}, (
            f"index alarm dimensions were {sorted(dims)!r}; they must name the table AND the index"
        )
    for name in table_alarms:
        ns, metric, dims = scopes[name]
        assert dims == {"TableName": table}, (
            f"table alarm dimensions were {sorted(dims)!r}; a base-table policy names the table only"
        )
    assert sorted(scopes[n][1] for n in index_alarms) == [
        "ConsumedReadCapacityUnits", "ConsumedReadCapacityUnits",
        "ProvisionedReadCapacityUnits", "ProvisionedReadCapacityUnits"], (
        f"index alarm metrics were {sorted(scopes[n][1] for n in index_alarms)!r}"
    )

    aas.deregister_scalable_target(ServiceNamespace="dynamodb", ResourceId=index_id,
                                   ScalableDimension=_IDX_DIM)

    assert _policies(aas, index_id) == [], "the index policy outlived its deregistered target"
    survivors = [p["PolicyName"] for p in _policies(aas, table_id)]
    assert survivors == [table_policy], (
        f"after deregistering the INDEX target the table's policies were {survivors!r}"
    )
    remaining = _poll_until(lambda: _alarm_scopes(cw, table_alarms + index_alarms),
                            lambda s: not set(index_alarms) & set(s), timeout_s=180, interval_s=5.0,
                            description="the index policy's alarms being removed")
    assert set(remaining) == set(table_alarms), (
        f"{len(set(table_alarms) - set(remaining))} of the table policy's 4 alarms were removed "
        f"by deregistering the index target"
    )
    tables = aas.describe_scalable_targets(ServiceNamespace="dynamodb",
                                           ResourceIds=[table_id])["ScalableTargets"]
    assert [t["ScalableDimension"] for t in tables] == [_TBL_DIM], (
        f"table targets after the index deregister: {[t['ScalableDimension'] for t in tables]!r}"
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
