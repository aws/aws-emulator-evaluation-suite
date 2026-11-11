"""ddb-consumed-capacity-two-plane-numeric-agreement."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-consumed-capacity-two-plane-numeric-agreement"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "dynamodb"]

#: Item blob sizes chosen to straddle the 1 KB write-capacity boundary in three places, and the
#: 4 KB read boundary in one: 5 items of ~200 B (1 WCU each), 5 of ~1200 B (2 WCU), 5 of ~3500 B
#: (4 WCU). Expected total 35 WCU -- a number no round constant and no per-request count
#: (15) matches. Measured on real AWS.
_SIZES = (("s", 200, 5), ("m", 1200, 5), ("l", 3500, 5))
_N_WRITES = sum(n for _, _, n in _SIZES)
_EXPECTED_WCU = 35.0

#: Reads: 5 eventually-consistent GetItems on ~200 B items (0.5 RCU each), 5 strongly-consistent
#: on the same items (1.0 RCU each), 5 eventually-consistent on the ~3500 B items (0.5 RCU each,
#: still one 4 KB unit), and one Query returning all 15 items. MEASURED: the Query costs 3.5 RCU
#: -- the RCU is computed once over the TOTAL bytes returned and halved, not per item. Per-item
#: charging would be 15 * 0.5 = 7.5.
_N_READ_CALLS = 16
_EXPECTED_QUERY_RCU = 3.5
_EXPECTED_RCU = 13.5

#: The largest single write cost (the ~3500 B items) and the largest single read cost (the Query,
#: charged once over the total bytes returned). Both are the per-request MAXIMUM over the window,
#: which is how this check proves the metric plane stores one sample PER REQUEST rather than one
#: lumped total: a single datapoint carrying the total would report Maximum 35.0 / 13.5.
_EXPECTED_MAX_WCU_SAMPLE = 4.0
_EXPECTED_MAX_RCU_SAMPLE = 3.5

#: MEASURED: the metric was readable 40 s after the last request and its Sum and Maximum were
#: unchanged for the next 8 minutes. The window two equal readings must be separated by before an
#: exact value is trusted.
_STABLE_WINDOW_S = 60
_HOLD_S = 45


# ===== helpers =====
def _poll_until_stable(ctx, probe, *, window_s, timeout_s, interval_s=2, description="reading"):
    """Return probe()'s value once two readings >= window_s apart are EQUAL and non-empty.

    Stopping at the first reading that REACHES the target only detects an under-count; an
    emulator that emits the right total early and more later would pass. An empty reading resets
    the anchor, so this never "stabilises" on absence. The timeout is capped by the runner's
    remaining time.
    """
    left = ctx.time_left()
    budget = timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))
    deadline = time.monotonic() + budget
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if not last:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} never held one value for {window_s}s within {budget:.0f}s; "
        f"last reading was {last!r}"
    )


def _assert_stays(probe, expected, *, hold_s, interval_s=2, description="reading"):
    """Assert probe() == expected continuously for hold_s."""
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description} became {got!r}, expected it to stay {expected!r} for {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


def _error(fn):
    """The AWS (code, message) raised by fn(). Raises if fn() SUCCEEDS -- a falsy sentinel there
    would turn 'the emulator accepted input real AWS rejects' into a naming difference."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    raise AssertionError(f"expected an AWS error, but the call succeeded with {result!r}")
# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html
@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """The ConsumedCapacity DynamoDB returns in-band (fractional read units, the Query's round-once
    rule) sums to exactly the AWS/DynamoDB capacity metrics for the same table, one sample per
    request, per-operation dimensions real, and a refused write charged on neither plane."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    table = ctx.unique_name("sim2real-behav-ddbcap-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                   {"AttributeName": "SK", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                              {"AttributeName": "SK", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)

    # --- act: accumulate the API plane's OWN arithmetic ---------------------------------- #
    api_wcu = 0.0
    for tag, nbytes, n in _SIZES:
        for i in range(n):
            resp = ddb.put_item(
                TableName=table, ReturnConsumedCapacity="TOTAL",
                Item={"PK": {"S": "g"}, "SK": {"S": f"{tag}{i}"},
                      "blob": {"S": "x" * nbytes}},
            )
            api_wcu += resp["ConsumedCapacity"]["CapacityUnits"]
            assert resp["ConsumedCapacity"]["TableName"] == table, (
                f"PutItem attributed capacity to {resp['ConsumedCapacity']['TableName']!r}, "
                f"not {table!r}"
            )

    # Pin the API plane's arithmetic BEFORE any metric is read, so a later disagreement can be
    # attributed to one plane rather than blamed on either.
    assert api_wcu == _EXPECTED_WCU, (
        f"the {_N_WRITES} PutItems reported {api_wcu!r} write capacity units in their own "
        f"responses, expected {_EXPECTED_WCU}. The item-size rule is 1 WCU per 1 KB rounded up, "
        f"and item size includes attribute names: 5 items of ~200 B cost 1 each, 5 of ~1200 B "
        f"cost 2 each, 5 of ~3500 B cost 4 each"
    )

    api_rcu = 0.0
    eventual_small = ddb.get_item(
        TableName=table, Key={"PK": {"S": "g"}, "SK": {"S": "s0"}},
        ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]
    assert eventual_small == 0.5, (
        f"an eventually-consistent GetItem on a ~200 B item cost {eventual_small!r} RCU, "
        f"expected 0.5 -- half a read unit per 4 KB. An integer here means the metric plane "
        f"cannot carry fractions either"
    )
    api_rcu += eventual_small
    for i in range(1, 5):
        api_rcu += ddb.get_item(
            TableName=table, Key={"PK": {"S": "g"}, "SK": {"S": f"s{i}"}},
            ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]

    strong_small = ddb.get_item(
        TableName=table, Key={"PK": {"S": "g"}, "SK": {"S": "s0"}}, ConsistentRead=True,
        ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]
    assert strong_small == 1.0, (
        f"a strongly-consistent GetItem on the same ~200 B item cost {strong_small!r} RCU, "
        f"expected 1.0 -- exactly twice the eventually-consistent cost"
    )
    api_rcu += strong_small
    for i in range(1, 5):
        api_rcu += ddb.get_item(
            TableName=table, Key={"PK": {"S": "g"}, "SK": {"S": f"s{i}"}}, ConsistentRead=True,
            ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]

    eventual_large = ddb.get_item(
        TableName=table, Key={"PK": {"S": "g"}, "SK": {"S": "l0"}},
        ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]
    assert eventual_large == 0.5, (
        f"an eventually-consistent GetItem on a ~3500 B item cost {eventual_large!r} RCU, "
        f"expected 0.5 -- still inside one 4 KB read unit, so it costs the same as the 200 B one"
    )
    api_rcu += eventual_large
    for i in range(1, 5):
        api_rcu += ddb.get_item(
            TableName=table, Key={"PK": {"S": "g"}, "SK": {"S": f"l{i}"}},
            ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]

    query = ddb.query(
        TableName=table, KeyConditionExpression="PK = :p",
        ExpressionAttributeValues={":p": {"S": "g"}}, ReturnConsumedCapacity="TOTAL")
    assert query["Count"] == _N_WRITES and "LastEvaluatedKey" not in query, (
        f"the Query returned {query['Count']} items with LastEvaluatedKey="
        f"{query.get('LastEvaluatedKey')!r}; all {_N_WRITES} must come back in one page for the "
        f"single-call capacity charge below to mean what it says"
    )
    query_rcu = query["ConsumedCapacity"]["CapacityUnits"]
    assert query_rcu == _EXPECTED_QUERY_RCU, (
        f"the Query over {_N_WRITES} items cost {query_rcu!r} RCU, expected "
        f"{_EXPECTED_QUERY_RCU}. The read units are computed ONCE over the total bytes returned "
        f"and then halved; charging per item would be {_N_WRITES * 0.5}, which is the single "
        f"hardest read-capacity rule to get right"
    )
    assert query_rcu != _N_WRITES * 0.5, (
        f"the Query cost exactly the per-item total {_N_WRITES * 0.5} -- capacity is being "
        f"charged per item instead of per rounded total"
    )
    api_rcu += query_rcu
    assert api_rcu == _EXPECTED_RCU, (
        f"the {_N_READ_CALLS} read calls reported {api_rcu!r} read capacity units in their own "
        f"responses, expected {_EXPECTED_RCU}"
    )

    # --- failure arm, placed BEFORE the metric window closes ----------------------------- #
    # A write that never happened must contribute to neither plane. Doing it here rather than
    # after the read means the stabilised metric value below ALREADY excludes it: an emulator
    # that charges capacity before authorising the request reads 36, not 35.
    refusal = _error(lambda: ddb.put_item(
        TableName=f"{table}-does-not-exist", ReturnConsumedCapacity="TOTAL",
        Item={"PK": {"S": "g"}, "SK": {"S": "ghost"}}))
    want = ("ResourceNotFoundException", "Requested resource not found")
    assert refusal == want, (
        f"PutItem against a non-existent table raised {refusal!r}, expected {want!r}"
    )

    end = datetime.now(timezone.utc) + timedelta(minutes=5)
    dims = [{"Name": "TableName", "Value": table}]

    def _agg(metric, extra_dims=(), stat="Sum"):
        """Aggregate one statistic across every Period=60 bucket in the window, or None.

        Only `Sum` and `Maximum` are read on the capacity metrics: DynamoDB back-fills them with
        zero-valued samples minutes later, which moves `SampleCount` and `Minimum`.
        """
        dps = cw.get_metric_statistics(
            Namespace="AWS/DynamoDB", MetricName=metric, Dimensions=dims + list(extra_dims),
            StartTime=window_start, EndTime=end, Period=60, Statistics=[stat])["Datapoints"]
        if not dps:
            return None
        if stat == "Maximum":
            return max(d["Maximum"] for d in dps)
        return sum(d[stat] for d in dps)

    # --- assert: the two planes agree ---------------------------------------------------- #
    def _snapshot():
        vals = (_agg("ConsumedWriteCapacityUnits"), _agg("ConsumedReadCapacityUnits"),
                _agg("ConsumedWriteCapacityUnits", stat="Maximum"),
                _agg("ConsumedReadCapacityUnits", stat="Maximum"))
        return vals if all(v is not None for v in vals) else None

    wcu_sum, rcu_sum, wcu_max, rcu_max = _poll_until_stable(
        ctx, _snapshot, window_s=_STABLE_WINDOW_S, timeout_s=200,
        description=f"AWS/DynamoDB consumed capacity for table {table!r}",
    )

    assert wcu_sum == api_wcu, (
        f"CloudWatch reports ConsumedWriteCapacityUnits Sum={wcu_sum!r} while DynamoDB's own "
        f"responses reported {api_wcu!r}. One accounting engine feeds both surfaces; the two "
        f"must agree exactly, including which requests were charged"
    )
    assert rcu_sum == api_rcu, (
        f"CloudWatch reports ConsumedReadCapacityUnits Sum={rcu_sum!r} while DynamoDB's own "
        f"responses reported {api_rcu!r}; the metric plane must carry the fractional half-units "
        f"too, not integers"
    )
    assert rcu_sum % 1.0 == 0.5, (
        f"ConsumedReadCapacityUnits Sum was {rcu_sum!r}, which has no fractional half -- the "
        f"eventually-consistent reads each cost 0.5 and an odd number of them was performed, so "
        f"an integral total means the halves were rounded away somewhere"
    )

    # Per-request granularity: the metric store holds one sample per REQUEST, so the largest
    # sample is the largest single request's cost. An emulator that publishes one datapoint
    # carrying the total satisfies both Sum assertions above and fails both of these.
    assert wcu_max == _EXPECTED_MAX_WCU_SAMPLE, (
        f"ConsumedWriteCapacityUnits Maximum was {wcu_max!r}, expected "
        f"{_EXPECTED_MAX_WCU_SAMPLE} -- the single most expensive write (a ~3500 B item, 4 WCU). "
        f"A single lumped datapoint would report {api_wcu}"
    )
    assert rcu_max == _EXPECTED_MAX_RCU_SAMPLE, (
        f"ConsumedReadCapacityUnits Maximum was {rcu_max!r}, expected "
        f"{_EXPECTED_MAX_RCU_SAMPLE} -- the Query's single charge, computed once over the total "
        f"bytes it returned. This is the strictest leg in the check: the Query's round-once RCU "
        f"has to arrive in the metric plane as ONE sample of exactly that value. A lumped "
        f"datapoint reports {api_rcu}; per-item charging reports {_N_WRITES * 0.5}"
    )

    # The per-operation dimension is real data, not one lumped series. SuccessfulRequestLatency
    # is not back-filled, so its SampleCount IS the request count.
    for op, want in (("PutItem", 15.0), ("GetItem", 15.0), ("Query", 1.0)):
        extra = [{"Name": "Operation", "Value": op}]
        samples = _agg("SuccessfulRequestLatency", extra, stat="SampleCount")
        assert samples is not None, (
            f"AWS/DynamoDB SuccessfulRequestLatency has no datapoints under "
            f"(TableName, Operation={op!r}); the per-operation dimension must be published"
        )
        assert samples == want, (
            f"SuccessfulRequestLatency SampleCount under Operation={op!r} was {samples!r}, "
            f"expected {want} -- the requests must be attributed per operation, not lumped"
        )

    # --- failure arm: the absences, held past a publication interval ---------------------- #
    def _absences():
        return {
            "ConsumedWriteCapacityUnits with no dimensions": cw.get_metric_statistics(
                Namespace="AWS/DynamoDB", MetricName="ConsumedWriteCapacityUnits", Dimensions=[],
                StartTime=window_start, EndTime=end, Period=60,
                Statistics=["Sum"])["Datapoints"],
            "the write plane's disagreement with the API plane": [
                v for v in [_agg("ConsumedWriteCapacityUnits")] if v != api_wcu
            ],
        }

    _assert_stays(
        _absences, {"ConsumedWriteCapacityUnits with no dimensions": [],
                    "the write plane's disagreement with the API plane": []},
        hold_s=_HOLD_S,
        description=(
            "the dimensionless ConsumedWriteCapacityUnits query (a service metric is keyed on "
            "its COMPLETE dimension set, so an empty set is a distinct empty series) and the "
            "write total's immunity to the rejected PutItem"
        ),
    )

    # --- positive control, after every negative ------------------------------------------- #
    control = _agg("ConsumedWriteCapacityUnits")
    assert control == api_wcu, (
        f"after the rejected write and the absence probes, the write plane reads {control!r}, "
        f"expected {api_wcu!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
