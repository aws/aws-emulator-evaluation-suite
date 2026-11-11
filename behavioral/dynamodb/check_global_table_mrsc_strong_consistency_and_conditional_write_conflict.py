"""global-table-mrsc-strong-consistency-and-conditional-write-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-table-mrsc-strong-consistency-and-conditional-write-conflict"
GROUP = "consistency"
SERVICES = ["dynamodb"]

# The Regions AWS documents for MRSC global tables. Any three of them may form one table, so the
# replica and witness are the first two of this list other than ctx.region.
_MRSC_REGIONS = (
    "us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-central-1", "ap-northeast-1",
    "ap-northeast-2", "ap-southeast-1", "ca-central-1", "eu-west-2", "eu-west-3", "eu-north-1",
    "eu-south-2", "ap-northeast-3", "ap-south-1",
)
_ACTIVE_WAIT_S = 900.0


def _mrsc_peers(region):
    """The replica and witness Regions for an MRSC table whose base table is in region."""
    assert region in _MRSC_REGIONS, (
        f"MRSC global tables are not available in {region!r}; documented Regions: {_MRSC_REGIONS}"
    )
    replica, witness = [r for r in _MRSC_REGIONS if r != region][:2]
    return replica, witness


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


_TTL_REJECTED_MESSAGE = (
    "Time To Live is not supported for global tables with MultiRegionConsistency set to STRONG."
)


def _error_code_and_message(fn):
    """The (Error.Code, Error.Message) fn() raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(ctx, probe, predicate, *, cap_s, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result), under a deadline capped by the run budget."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _delete_table_if_present(ddb, name):
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ResourceNotFoundException":
            return
        if err.get("Code") == "ResourceInUseException" and "being deleted" in err.get("Message", ""):
            return
        raise


def _teardown_global_table(ddb, name, replica_region, witness_region):
    """Remove the replica and witness, wait until both are gone, then delete the base table."""
    deadline = time.monotonic() + 600.0
    while True:
        try:
            ddb.update_table(
                TableName=name,
                ReplicaUpdates=[{"Delete": {"RegionName": replica_region}}],
                GlobalTableWitnessUpdates=[{"Delete": {"RegionName": witness_region}}],
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ResourceNotFoundException":
                return
            if err.get("Code") != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    while True:
        try:
            table = ddb.describe_table(TableName=name)["Table"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if not table.get("Replicas") and not table.get("GlobalTableWitnesses"):
            _delete_table_if_present(ddb, name)
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"replica/witness of {name} still present after teardown wait: "
                f"replicas={table.get('Replicas')} witnesses={table.get('GlobalTableWitnesses')}"
            )
        time.sleep(5.0)


@tags(
    "axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
    "concern:representation", "dp:api", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """An MRSC global table reports MultiRegionConsistency STRONG from every full-replica Region,
    a strongly consistent read in one Region sees a write that just completed in another, and a
    stale conditional write from a different Region fails against the cross-Region-latest version.
    """
    primary_region = ctx.region
    replica_region, witness_region = _mrsc_peers(primary_region)
    ddb1 = ctx.client("dynamodb")
    ddb2 = ctx.client("dynamodb", region=replica_region)

    table = ctx.unique_name("sim2real-behav-mrsc-")
    ddb1.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb1, table))
    _poll_until(
        ctx,
        lambda: ddb1.describe_table(TableName=table)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        cap_s=_ACTIVE_WAIT_S,
        description=f"{table} ACTIVE",
    )

    ddb1.update_table(
        TableName=table,
        MultiRegionConsistency="STRONG",
        ReplicaUpdates=[{"Create": {"RegionName": replica_region}}],
        GlobalTableWitnessUpdates=[{"Create": {"RegionName": witness_region}}],
    )
    ctx.on_cleanup(lambda: _teardown_global_table(ddb1, table, replica_region, witness_region))

    described = _poll_until(
        ctx,
        lambda: ddb1.describe_table(TableName=table)["Table"],
        lambda d: d["TableStatus"] == "ACTIVE"
        and any(r["RegionName"] == replica_region and r.get("ReplicaStatus") == "ACTIVE" for r in d.get("Replicas", []))
        and any(w["RegionName"] == witness_region and w.get("WitnessStatus") == "ACTIVE" for w in d.get("GlobalTableWitnesses", [])),
        cap_s=_ACTIVE_WAIT_S,
        interval_s=10.0,
        description="MRSC replica and witness ACTIVE via DescribeTable",
    )

    # (1) MultiRegionConsistency is reported as STRONG from the primary Region, and the replica
    # Region's own DescribeTable call -- not just the Region that issued the UpdateTable -- agrees.
    # A witness holds no table of its own in its Region, so it has no DescribeTable to call there.
    assert described["MultiRegionConsistency"] == "STRONG", (
        f"expected MultiRegionConsistency STRONG on {primary_region}, got {described.get('MultiRegionConsistency')!r}"
    )
    described_from_replica = ddb2.describe_table(TableName=table)["Table"]
    assert described_from_replica["MultiRegionConsistency"] == "STRONG", (
        f"expected MultiRegionConsistency STRONG from {replica_region}, got "
        f"{described_from_replica.get('MultiRegionConsistency')!r}"
    )
    replica_regions = {r["RegionName"] for r in described["Replicas"]}
    assert replica_regions == {replica_region}, f"expected replica Region {{{replica_region}}}, got {replica_regions}"
    witness_regions = {w["RegionName"] for w in described["GlobalTableWitnesses"]}
    assert witness_regions == {witness_region}, f"expected witness Region {{{witness_region}}}, got {witness_regions}"

    # (2) A write that completes in the primary Region is visible to a strongly consistent read
    # issued against the replica Region immediately afterward -- no propagation wait.
    ddb1.put_item(TableName=table, Item={"pk": {"S": "item-a"}, "v": {"S": "written-in-primary"}})
    cross_region_read = ddb2.get_item(TableName=table, Key={"pk": {"S": "item-a"}}, ConsistentRead=True)
    assert cross_region_read.get("Item") == {"pk": {"S": "item-a"}, "v": {"S": "written-in-primary"}}, (
        f"expected the primary-Region write visible via a strongly consistent read in "
        f"{replica_region}, got {cross_region_read.get('Item')!r}"
    )

    # (3) A conditional write succeeds once in the primary Region; a second conditional write from
    # the replica Region, carrying the now-stale precondition, is evaluated against that same
    # cross-Region-latest version and fails -- it is not racing a locally stale copy.
    ddb1.put_item(TableName=table, Item={"pk": {"S": "item-b"}, "ctr": {"N": "0"}})
    ddb1.update_item(
        TableName=table,
        Key={"pk": {"S": "item-b"}},
        UpdateExpression="SET ctr = :new",
        ConditionExpression="ctr = :old",
        ExpressionAttributeValues={":new": {"N": "1"}, ":old": {"N": "0"}},
    )
    code, message = _error_code_and_message(
        lambda: ddb2.update_item(
            TableName=table,
            Key={"pk": {"S": "item-b"}},
            UpdateExpression="SET ctr = :new",
            ConditionExpression="ctr = :old",
            ExpressionAttributeValues={":new": {"N": "2"}, ":old": {"N": "0"}},
        )
    )
    assert code == "ConditionalCheckFailedException", f"expected ConditionalCheckFailedException, got {code} ({message})"
    assert message == "The conditional request failed", f"unexpected message {message!r}"
    winner = ddb1.get_item(TableName=table, Key={"pk": {"S": "item-b"}}, ConsistentRead=True)["Item"]
    assert winner == {"pk": {"S": "item-b"}, "ctr": {"N": "1"}}, (
        f"expected the primary Region's write (ctr=1) to stand, got {winner!r}"
    )
    winner_from_replica = ddb2.get_item(TableName=table, Key={"pk": {"S": "item-b"}}, ConsistentRead=True)["Item"]
    assert winner_from_replica == winner, (
        f"expected the same winning value from {replica_region}, got {winner_from_replica!r} vs {winner!r}"
    )

    # (4) TTL is a documented unsupported setting for MRSC and is refused with its exact message.
    code, message = _error_code_and_message(
        lambda: ddb1.update_time_to_live(
            TableName=table, TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"}
        )
    )
    assert code == "ValidationException", f"expected ValidationException enabling TTL on an MRSC table, got {code}"
    assert message == _TTL_REJECTED_MESSAGE, f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
