"""gsi-scalable-target-moves-the-index-not-the-table."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-scalable-target-moves-the-index-not-the-table"
GROUP = "scalable-targets"
SERVICES = ["application-autoscaling"]

_IDX_DIM = "dynamodb:index:ReadCapacityUnits"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registering a GSI's read dimension with MinCapacity above the index's provisioned read
    capacity raises the INDEX to that minimum, leaves the base table's capacity alone, and records
    the scaling activity against the index resource id (`table/<t>/index/<i>`), not the table's.
    """
    aas = ctx.client("application-autoscaling")
    ddb = ctx.client("dynamodb")
    index = "by-gk"
    table = _create_table(ctx, index=index)
    table_id = f"table/{table}"
    index_id = f"table/{table}/index/{index}"

    _register(ctx, aas, index_id, _IDX_DIM, 3, 10)

    targets = aas.describe_scalable_targets(ServiceNamespace="dynamodb", ResourceIds=[index_id],
                                            ScalableDimension=_IDX_DIM)["ScalableTargets"]
    assert [(t["ResourceId"], t["MinCapacity"], t["MaxCapacity"]) for t in targets] == [
        (index_id, 3, 10)], f"index target read back as {targets!r}, expected one (3, 10) target"

    def _gsi_and_table():
        desc = ddb.describe_table(TableName=table)["Table"]
        gsi = desc["GlobalSecondaryIndexes"][0]
        return (desc["TableStatus"], gsi["IndexStatus"],
                gsi["ProvisionedThroughput"]["ReadCapacityUnits"],
                gsi["ProvisionedThroughput"]["WriteCapacityUnits"],
                desc["ProvisionedThroughput"]["ReadCapacityUnits"],
                desc["ProvisionedThroughput"]["WriteCapacityUnits"])

    state = _poll_until(_gsi_and_table, lambda s: s[:3] == ("ACTIVE", "ACTIVE", 3), timeout_s=180,
                        description=f"GSI {index!r} read capacity reaching the registered minimum 3")
    assert state[3] == 1, f"GSI write capacity moved to {state[3]}; only the read dimension is registered"
    assert (state[4], state[5]) == (1, 1), (
        f"base table capacity moved to read={state[4]} write={state[5]}; a target on the index "
        f"must leave the table at its provisioned 1/1"
    )

    activities = aas.describe_scaling_activities(ServiceNamespace="dynamodb", ResourceId=index_id,
                                                 ScalableDimension=_IDX_DIM)["ScalingActivities"]
    assert len(activities) == 1, f"expected exactly one activity on the index, got {activities!r}"
    act = activities[0]
    assert (act["ResourceId"], act["ScalableDimension"]) == (index_id, _IDX_DIM), (
        f"activity carried ({act['ResourceId']!r}, {act['ScalableDimension']!r})"
    )
    assert act["Description"] == "Setting read capacity units to 3.", (
        f"activity description was {act['Description']!r}"
    )
    assert act["Cause"] == "minimum capacity was set to 3", f"activity cause was {act['Cause']!r}"

    table_acts = aas.describe_scaling_activities(ServiceNamespace="dynamodb",
                                                 ResourceId=table_id)["ScalingActivities"]
    assert table_acts == [], f"the base table got activities it never had a target for: {table_acts!r}"


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
