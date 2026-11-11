"""metrics-dynamodb-gsi-consumption-under-index-dimension-not-folded-into-table."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-dynamodb-gsi-consumption-under-index-dimension-not-folded-into-table"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

_INDEX = "by-group"
_PROJECTED = 4        # items carrying the GSI key: 1 WCU base + 1 WCU index each
_SPARSE = 2           # items WITHOUT the GSI key: 1 WCU base, nothing on the index
_BASE_READS = 2       # eventually consistent base GetItems of sub-4KB items: 0.5 RCU each
_BLOB = "y" * 100

#: Measured on real AWS on this shape: a projected PutItem reports
#: Table=1.0 + GSI=1.0 (TOTAL 2.0), a sparse PutItem Table=1.0 and no GSI member, a GSI Query
#: Table=0.0 + GSI=0.5; CloudWatch {TableName} WCU carried ONLY the base-table portion, and
#: {TableName, GlobalSecondaryIndexName} carried the index portion.
_EXPECTED_BASE_WCU = float(_PROJECTED + _SPARSE)       # 6.0
_EXPECTED_GSI_WCU = float(_PROJECTED)                  # 4.0
_EXPECTED_BASE_RCU = 0.5 * _BASE_READS                 # 1.0

_INDEX_CATCHUP_S = 60
_METRIC_TIMEOUT_S = 200
_HOLD_S = 30


# ===== helpers =====
def _series(cw, metric, dims, start, end, stat="Sum"):
    """One statistic of an AWS/DynamoDB series over the window, or None if it has no datapoints."""
    dps = cw.get_metric_statistics(
        Namespace="AWS/DynamoDB", MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in dims],
        StartTime=start, EndTime=end, Period=60, Statistics=[stat])["Datapoints"]
    if not dps:
        return None
    if stat == "Maximum":
        return max(d[stat] for d in dps)
    return sum(d[stat] for d in dps)


def _await_exact(ctx, probe, expected, *, timeout_s, hold_s, interval_s=2, description):
    """Poll probe() every 2 s until it EQUALS expected (ceiling capped by the runner's remaining
    time), then require it to hold for hold_s, so a late over-count fails with the reading quoted."""
    left = ctx.time_left()
    budget = timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))
    deadline = time.monotonic() + budget
    last = None
    while True:
        last = probe()
        if last == expected:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: never equalled {expected!r} within {budget:.0f}s; "
                f"last reading {last!r}")
        time.sleep(interval_s)
    hold_until = time.monotonic() + hold_s
    while time.monotonic() < hold_until:
        time.sleep(interval_s)
        got = probe()
        assert got == expected, (
            f"{description}: reached {expected!r} and then moved to {got!r}")
    return last
# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:metrics",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """GSI consumption is published under {TableName, GlobalSecondaryIndexName}, not folded into the
    {TableName} series: each series carries exactly the units the API itemised for it, and a sparse
    write that never reached the index adds nothing to the index series."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    table = ctx.unique_name("sim2real-xsvc-ddbm-gsi-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "gk", "AttributeType": "S"}],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "gk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    start = datetime.now(timezone.utc) - timedelta(minutes=2)

    api_base_wcu = api_gsi_wcu = api_total_wcu = 0.0
    for i in range(_PROJECTED):
        cc = ddb.put_item(TableName=table,
                          Item={"pk": {"S": f"p{i}"}, "gk": {"S": "G"}, "b": {"S": _BLOB}},
                          ReturnConsumedCapacity="INDEXES")["ConsumedCapacity"]
        gsi = cc.get("GlobalSecondaryIndexes", {}).get(_INDEX, {}).get("CapacityUnits")
        assert (cc["Table"]["CapacityUnits"], gsi) == (1.0, 1.0), (
            f"a projected write should itemise Table=1.0 and {_INDEX}=1.0, got {cc!r}")
        api_base_wcu += cc["Table"]["CapacityUnits"]
        api_gsi_wcu += gsi
        api_total_wcu += cc["CapacityUnits"]
    for i in range(_SPARSE):
        cc = ddb.put_item(TableName=table,
                          Item={"pk": {"S": f"s{i}"}, "b": {"S": _BLOB}},
                          ReturnConsumedCapacity="INDEXES")["ConsumedCapacity"]
        assert cc["Table"]["CapacityUnits"] == 1.0 and "GlobalSecondaryIndexes" not in cc, (
            f"a write without the index key must bill the base table only, got {cc!r}")
        api_base_wcu += cc["Table"]["CapacityUnits"]
        api_total_wcu += cc["CapacityUnits"]
    assert (api_base_wcu, api_gsi_wcu) == (_EXPECTED_BASE_WCU, _EXPECTED_GSI_WCU), (
        f"API itemised base={api_base_wcu!r} gsi={api_gsi_wcu!r}, expected "
        f"{_EXPECTED_BASE_WCU!r} and {_EXPECTED_GSI_WCU!r}")

    api_base_rcu = 0.0
    for i in range(_BASE_READS):
        cc = ddb.get_item(TableName=table, Key={"pk": {"S": f"p{i}"}},
                          ReturnConsumedCapacity="INDEXES")["ConsumedCapacity"]
        api_base_rcu += cc["Table"]["CapacityUnits"]
    assert api_base_rcu == _EXPECTED_BASE_RCU, (
        f"{_BASE_READS} eventual base GetItems itemised {api_base_rcu!r} RCU, expected "
        f"{_EXPECTED_BASE_RCU!r}")

    # GSI Queries: the index is eventually consistent, so re-query until it shows every projected
    # item. EVERY query is billed, so every query's itemised units are accumulated, and the base
    # table's share of each must be zero.
    api_gsi_rcu = 0.0
    queries = 0
    deadline = time.monotonic() + _INDEX_CATCHUP_S
    while True:
        q = ddb.query(TableName=table, IndexName=_INDEX, KeyConditionExpression="gk = :g",
                      ExpressionAttributeValues={":g": {"S": "G"}},
                      ReturnConsumedCapacity="INDEXES")
        cc = q["ConsumedCapacity"]
        queries += 1
        assert cc["Table"]["CapacityUnits"] == 0.0, (
            f"a Query served by {_INDEX} billed the base table {cc['Table']!r}; expected 0.0")
        api_gsi_rcu += cc["GlobalSecondaryIndexes"][_INDEX]["CapacityUnits"]
        keys = sorted(it["pk"]["S"] for it in q["Items"])
        if keys == [f"p{i}" for i in range(_PROJECTED)]:
            break
        assert time.monotonic() < deadline, (
            f"{_INDEX} never showed the {_PROJECTED} projected items within "
            f"{_INDEX_CATCHUP_S}s; last Query returned {keys!r} (sparse items must never appear)")
        time.sleep(2)
    assert api_gsi_rcu > 0.0, f"{queries} GSI Queries itemised no index read units"

    end = datetime.now(timezone.utc) + timedelta(minutes=5)
    base = [("TableName", table)]
    idx = base + [("GlobalSecondaryIndexName", _INDEX)]

    def _snapshot():
        return {
            "base WCU": _series(cw, "ConsumedWriteCapacityUnits", base, start, end),
            "gsi WCU": _series(cw, "ConsumedWriteCapacityUnits", idx, start, end),
            "base RCU": _series(cw, "ConsumedReadCapacityUnits", base, start, end),
            "gsi RCU": _series(cw, "ConsumedReadCapacityUnits", idx, start, end),
            "index-name-only WCU": _series(
                cw, "ConsumedWriteCapacityUnits",
                [("GlobalSecondaryIndexName", _INDEX)], start, end),
        }

    _await_exact(
        ctx, _snapshot,
        {"base WCU": api_base_wcu,
         "gsi WCU": api_gsi_wcu,
         "base RCU": api_base_rcu,
         "gsi RCU": api_gsi_rcu,
         "index-name-only WCU": None},
        timeout_s=_METRIC_TIMEOUT_S, hold_s=_HOLD_S,
        description=(f"AWS/DynamoDB per-index accounting for {table!r}: API itemised base "
                     f"WCU {api_base_wcu!r}, {_INDEX} WCU {api_gsi_wcu!r} (TOTAL "
                     f"{api_total_wcu!r} -- the value a FOLDED base series would show), base RCU "
                     f"{api_base_rcu!r}, {_INDEX} RCU {api_gsi_rcu!r} over {queries} Queries"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
