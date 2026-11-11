"""obs-dynamodb-3-provisioned-write-capacity-tracks-update-on-demand-has-none."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-dynamodb-3-provisioned-write-capacity-tracks-update-on-demand-has-none"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

_NS = "AWS/DynamoDB"
_METRIC = "ProvisionedWriteCapacityUnits"
_WCU_CREATE = 3
_WCU_UPDATED = 4
_RCU = 1
_TWIN_WRITES = 4
_BUDGET_S = 900
_HOLD_S = 30
_INTERVAL_S = 2


def _exact_dimension_sets(cw, metric, table):
    """Every dimension set list_metrics reports for (AWS/DynamoDB, metric) on this table."""
    sets = []
    for page in cw.get_paginator("list_metrics").paginate(
            Namespace=_NS, MetricName=metric,
            Dimensions=[{"Name": "TableName", "Value": table}]):
        for m in page["Metrics"]:
            sets.append(sorted((d["Name"], d["Value"]) for d in m["Dimensions"]))
    return sets


def _datapoints(cw, metric, table, stat, start):
    end = datetime.now(timezone.utc) + timedelta(minutes=5)
    dps = cw.get_metric_statistics(
        Namespace=_NS, MetricName=metric,
        Dimensions=[{"Name": "TableName", "Value": table}],
        StartTime=start, EndTime=end, Period=60, Statistics=[stat])["Datapoints"]
    return sorted(dps, key=lambda d: d["Timestamp"])


def _latest_max(cw, table, start):
    """Maximum of the most recent ProvisionedWriteCapacityUnits datapoint, or None."""
    dps = _datapoints(cw, _METRIC, table, "Maximum", start)
    return dps[-1]["Maximum"] if dps else None


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_exact(probe, expected, *, deadline, hold_s, interval_s, description, ctx=None):
    """Poll probe() until it EQUALS expected, then require it to hold for hold_s (two-sided:
    a wrong value never equals expected and fails at the ceiling with the reading quoted)."""
    last = None
    while True:
        last = probe()
        if last == expected:
            break
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description}: never equalled {expected!r} before the wait ceiling; "
                f"last reading {last!r}")
        time.sleep(interval_s)
    hold_until = time.monotonic() + hold_s
    while time.monotonic() < hold_until:
        time.sleep(interval_s)
        got = probe()
        assert got == expected, f"{description}: reached {expected!r} and then moved to {got!r}"
    return last


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """ProvisionedWriteCapacityUnits{TableName} reports the create-time WCU, follows UpdateTable to
    the new value and holds; an on-demand twin that has published ConsumedWriteCapacityUnits has
    an empty series for the metric, since it never populates under PAY_PER_REQUEST.
    """
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")

    prov = ctx.unique_name("sim2real-xsvc-ddbm-pwp-")
    ddb.create_table(
        TableName=prov, BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": _RCU, "WriteCapacityUnits": _WCU_CREATE},
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=prov))
    twin = ctx.unique_name("sim2real-xsvc-ddbm-pwo-")
    ddb.create_table(
        TableName=twin, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=twin))
    for t in (prov, twin):
        ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    start = datetime.now(timezone.utc) - timedelta(minutes=5)
    for i in range(_TWIN_WRITES):
        ddb.put_item(TableName=twin, Item={"pk": {"S": f"k{i}"}, "v": {"S": "x"}})

    deadline = time.monotonic() + _budget_s(ctx, _BUDGET_S)

    # Leg 1: discoverable under EXACTLY {TableName}, then the create-time value.
    _await_exact(
        lambda: [("TableName", prov)] in _exact_dimension_sets(cw, _METRIC, prov),
        True, deadline=deadline, ctx=ctx, hold_s=0, interval_s=_INTERVAL_S,
        description=f"list_metrics({_NS}, {_METRIC}, TableName={prov!r}) exact dimension set")
    _await_exact(lambda: _latest_max(cw, prov, start), float(_WCU_CREATE), deadline=deadline, ctx=ctx,
                 hold_s=0, interval_s=_INTERVAL_S,
                 description=f"{_METRIC} latest Maximum for {prov!r} at create")

    # Leg 2: raise the capacity; the latest datapoint follows and holds.
    ddb.update_table(TableName=prov, ProvisionedThroughput={
        "ReadCapacityUnits": _RCU, "WriteCapacityUnits": _WCU_UPDATED})
    ddb.get_waiter("table_exists").wait(TableName=prov, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    desc = ddb.describe_table(TableName=prov)["Table"]
    assert desc["TableStatus"] == "ACTIVE", f"{prov!r} status {desc['TableStatus']!r} after update"
    assert desc["ProvisionedThroughput"]["WriteCapacityUnits"] == _WCU_UPDATED, (
        f"DescribeTable reports WCU {desc['ProvisionedThroughput']['WriteCapacityUnits']!r} "
        f"after UpdateTable to {_WCU_UPDATED}")
    deadline = time.monotonic() + _budget_s(ctx, _BUDGET_S)
    _await_exact(lambda: _latest_max(cw, prov, start), float(_WCU_UPDATED), deadline=deadline, ctx=ctx,
                 hold_s=_HOLD_S, interval_s=_INTERVAL_S,
                 description=f"{_METRIC} latest Maximum for {prov!r} after UpdateTable")
    # Minimum and Maximum together: both capacities show even when they share one 60 s bucket.
    history = {d["Maximum"] for d in _datapoints(cw, _METRIC, prov, "Maximum", start)}
    history |= {d["Minimum"] for d in _datapoints(cw, _METRIC, prov, "Minimum", start)}
    assert history == {float(_WCU_CREATE), float(_WCU_UPDATED)}, (
        f"{_METRIC} history for {prov!r} holds {sorted(history)!r}; expected exactly the create "
        f"and updated capacities")

    # Leg 3: the on-demand twin. Barrier first -- its OWN consumption series has published --
    # then its provisioned-capacity series must be empty, not zero.
    _await_exact(
        lambda: sum(d["Sum"] for d in _datapoints(
            cw, "ConsumedWriteCapacityUnits", twin, "Sum", start)),
        float(_TWIN_WRITES), deadline=deadline, ctx=ctx, hold_s=0, interval_s=_INTERVAL_S,
        description=f"ConsumedWriteCapacityUnits Sum for on-demand twin {twin!r}")
    twin_series = _datapoints(cw, _METRIC, twin, "Maximum", start)
    assert twin_series == [], (
        f"on-demand twin {twin!r} must have NO {_METRIC} datapoints; got {twin_series!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
