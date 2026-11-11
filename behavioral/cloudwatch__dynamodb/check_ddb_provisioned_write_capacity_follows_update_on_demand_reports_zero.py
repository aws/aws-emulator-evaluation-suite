"""ddb-provisioned-write-capacity-follows-update-on-demand-reports-zero."""
from __future__ import annotations

import time
from datetime import timedelta
from email.utils import parsedate_to_datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-provisioned-write-capacity-follows-update-on-demand-reports-zero"
GROUP = "metric-emission"
SERVICES = ["dynamodb"]

_WCU_CREATE = 3
_WCU_UPDATED = 4
_RCU = 1
_TWIN_WRITES = 4
_SKEW_S = 120

_NOOP_MESSAGE = (
    "The provisioned throughput for the table will not change. The requested value equals "
    "the current value. Current ReadCapacityUnits provisioned for the table: {rcu}. Requested "
    "ReadCapacityUnits: {rcu}. Current WriteCapacityUnits provisioned for the table: {wcu}. "
    "Requested WriteCapacityUnits: {wcu}. Refer to the Amazon DynamoDB Developer Guide for "
    "current limits and how to request higher limits."
)


def _server_time(response):
    """The server's clock at ``response``, from its HTTP Date header (one-second resolution)."""
    return parsedate_to_datetime(response["ResponseMetadata"]["HTTPHeaders"]["date"])


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an accepted call fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was accepted where a refusal was required: {result!r}")


def _delete_table(ddb, name):
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(ctx, ddb, name):
    deadline = time.monotonic() + max(5.0, min(300.0, (ctx.time_left() or 300.0) - 5.0))
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=name)["Table"]
        if last["TableStatus"] == "ACTIVE":
            return last
        time.sleep(2)
    raise AssertionError(f"table {name!r} never reached ACTIVE; last status {last and last['TableStatus']!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTable reports the create-time WCU, follows UpdateTable to the new value with
    LastIncreaseDateTime at the update, and refuses a no-op update with the exact message; an
    on-demand twin that took writes reports zero provisioned capacity under PAY_PER_REQUEST.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ProvisionedThroughputDescription.html
    """
    ddb = ctx.client("dynamodb")

    prov = ctx.unique_name("sim2real-xsvc-ddbm-pwp-")
    ddb.create_table(
        TableName=prov, BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": _RCU, "WriteCapacityUnits": _WCU_CREATE},
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, prov))
    twin = ctx.unique_name("sim2real-xsvc-ddbm-pwo-")
    ddb.create_table(
        TableName=twin, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, twin))

    # Leg 1: the create-time capacity, and no increase recorded yet.
    created = _wait_active(ctx, ddb, prov)["ProvisionedThroughput"]
    assert (created["ReadCapacityUnits"], created["WriteCapacityUnits"]) == (_RCU, _WCU_CREATE), (
        f"DescribeTable reports {created!r} for a table created with RCU {_RCU} / WCU {_WCU_CREATE}")
    assert "LastIncreaseDateTime" not in created, (
        f"a table never updated reports LastIncreaseDateTime {created.get('LastIncreaseDateTime')!r}")

    # Leg 2: a no-op update is refused and changes nothing.
    code, message = _error(lambda: ddb.update_table(TableName=prov, ProvisionedThroughput={
        "ReadCapacityUnits": _RCU, "WriteCapacityUnits": _WCU_CREATE}))
    assert code == "ValidationException", f"no-op UpdateTable refused with {code!r}"
    expected = _NOOP_MESSAGE.format(rcu=_RCU, wcu=_WCU_CREATE)
    assert message == expected, f"no-op UpdateTable message {message!r}, expected {expected!r}"

    # Leg 3: raise the capacity; DescribeTable follows and stamps the increase.
    update = ddb.update_table(TableName=prov, ProvisionedThroughput={
        "ReadCapacityUnits": _RCU, "WriteCapacityUnits": _WCU_UPDATED})
    updated_at = _server_time(update)
    after = _wait_active(ctx, ddb, prov)["ProvisionedThroughput"]
    assert (after["ReadCapacityUnits"], after["WriteCapacityUnits"]) == (_RCU, _WCU_UPDATED), (
        f"DescribeTable reports {after!r} after UpdateTable to WCU {_WCU_UPDATED}")
    increased = after.get("LastIncreaseDateTime")
    assert increased is not None, f"an increased table carries no LastIncreaseDateTime: {after!r}"
    low, high = updated_at - timedelta(seconds=_SKEW_S), updated_at + timedelta(seconds=_SKEW_S)
    assert low <= increased <= high, (
        f"LastIncreaseDateTime {increased.isoformat()} is not within {_SKEW_S} s of the UpdateTable "
        f"response time {updated_at.isoformat()}")
    assert after["NumberOfDecreasesToday"] == 0, (
        f"NumberOfDecreasesToday is {after['NumberOfDecreasesToday']!r} on a table only increased")

    # Leg 4: the on-demand twin, after taking writes, reports zero provisioned capacity.
    _wait_active(ctx, ddb, twin)
    for i in range(_TWIN_WRITES):
        ddb.put_item(TableName=twin, Item={"pk": {"S": f"k{i}"}, "v": {"S": "x"}})
    desc = ddb.describe_table(TableName=twin)["Table"]
    assert desc["BillingModeSummary"]["BillingMode"] == "PAY_PER_REQUEST", (
        f"on-demand twin reports BillingModeSummary {desc.get('BillingModeSummary')!r}")
    pt = desc["ProvisionedThroughput"]
    assert (pt["ReadCapacityUnits"], pt["WriteCapacityUnits"], pt["NumberOfDecreasesToday"]) == (0, 0, 0), (
        f"on-demand twin reports ProvisionedThroughput {pt!r}; PAY_PER_REQUEST reports 0 / 0 / 0")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
