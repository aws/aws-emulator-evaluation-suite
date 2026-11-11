"""global-table-mrsc-unsupported-configuration-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-table-mrsc-unsupported-configuration-rejected"
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


_WRONG_REPLICA_COUNT_MESSAGE = (
    "Unsupported replica count for global tables with MultiRegionConsistency set to STRONG."
)
_LSI_UNSUPPORTED_MESSAGE = (
    "Local secondary indexes are not supported for global tables with MultiRegionConsistency set to STRONG."
)


def _error_code_and_message(fn):
    """The (Error.Code, Error.Message) fn() raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


def _await_active(ctx, ddb, name):
    """Wait until the table is ACTIVE."""
    _poll_until(
        ctx,
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        cap_s=_ACTIVE_WAIT_S,
        description=f"{name} ACTIVE",
    )


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable refuses MultiRegionConsistency STRONG with only one additional replica Region,
    and on a table carrying a local secondary index, each with its documented message; the same
    table then accepts a STRONG request with one replica and one witness.
    """
    ddb = ctx.client("dynamodb")
    replica_region, witness_region = _mrsc_peers(ctx.region)

    one_replica_table = ctx.unique_name("sim2real-behav-mrsc-count-")
    ddb.create_table(
        TableName=one_replica_table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, one_replica_table))
    _await_active(ctx, ddb, one_replica_table)

    # (4a) MRSC must span exactly 3 Regions; one replica (2 Regions total) is refused outright,
    # before any cross-Region provisioning starts. Step (4c) is the accepted control on this table.
    code, message = _error_code_and_message(
        lambda: ddb.update_table(
            TableName=one_replica_table,
            MultiRegionConsistency="STRONG",
            ReplicaUpdates=[{"Create": {"RegionName": replica_region}}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a 1-replica STRONG request, got {code}"
    assert message == _WRONG_REPLICA_COUNT_MESSAGE, f"unexpected message {message!r}"
    unchanged = ddb.describe_table(TableName=one_replica_table)["Table"]
    assert unchanged.get("Replicas", []) == [], f"expected no replica provisioned, got {unchanged.get('Replicas')}"
    assert "MultiRegionConsistency" not in unchanged, (
        f"expected no MultiRegionConsistency set on the refused table, got {unchanged.get('MultiRegionConsistency')!r}"
    )

    # (4b) Local secondary indexes are incompatible with MRSC; a table carrying one is refused
    # before any replica or witness is created.
    lsi_table = ctx.unique_name("sim2real-behav-mrsc-lsi-")
    ddb.create_table(
        TableName=lsi_table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "lsik", "AttributeType": "S"},
        ],
        LocalSecondaryIndexes=[
            {
                "IndexName": "lsi1",
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "lsik", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, lsi_table))
    _await_active(ctx, ddb, lsi_table)

    code, message = _error_code_and_message(
        lambda: ddb.update_table(
            TableName=lsi_table,
            MultiRegionConsistency="STRONG",
            ReplicaUpdates=[{"Create": {"RegionName": replica_region}}],
            GlobalTableWitnessUpdates=[{"Create": {"RegionName": witness_region}}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException for an LSI-carrying STRONG request, got {code}"
    assert message == _LSI_UNSUPPORTED_MESSAGE, f"unexpected message {message!r}"
    unchanged_lsi = ddb.describe_table(TableName=lsi_table)["Table"]
    assert unchanged_lsi.get("Replicas", []) == [], f"expected no replica provisioned, got {unchanged_lsi.get('Replicas')}"
    assert unchanged_lsi.get("GlobalTableWitnesses", []) == [], (
        f"expected no witness provisioned, got {unchanged_lsi.get('GlobalTableWitnesses')}"
    )

    # (4c) The empty, LSI-free table refused in (4a) accepts STRONG with one replica and one
    # witness, so the refusals above are the replica count and the LSI, not MRSC itself.
    ddb.update_table(
        TableName=one_replica_table,
        MultiRegionConsistency="STRONG",
        ReplicaUpdates=[{"Create": {"RegionName": replica_region}}],
        GlobalTableWitnessUpdates=[{"Create": {"RegionName": witness_region}}],
    )
    ctx.on_cleanup(lambda: _teardown_global_table(ddb, one_replica_table, replica_region, witness_region))
    _poll_until(
        ctx,
        lambda: ddb.describe_table(TableName=one_replica_table)["Table"],
        lambda d: d.get("MultiRegionConsistency") == "STRONG"
        and {r["RegionName"] for r in d.get("Replicas", [])} == {replica_region}
        and {w["RegionName"] for w in d.get("GlobalTableWitnesses", [])} == {witness_region},
        cap_s=_ACTIVE_WAIT_S,
        interval_s=5.0,
        description="DescribeTable lists the accepted replica and witness with MultiRegionConsistency STRONG",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
