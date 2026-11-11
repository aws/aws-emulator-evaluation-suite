"""describe-global-table-not-found-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-global-table-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeGlobalTable (version 2017.11.29) raises GlobalTableNotFoundException with the exact message for a
    never-created name and for an ACTIVE version 2019.11.21 global table with two replica regions, which
    ListGlobalTables does not list either.
    """
    ddb = ctx.client("dynamodb")
    region1 = ctx.region
    # A global table replica must be in a genuinely different AWS region than
    # ctx.region, so this pair is pinned rather than derived.
    region2 = "us-west-2" if region1 != "us-west-2" else "us-east-1"
    table_name = ctx.unique_name("sim2real-behav-gt-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
    )
    ctx.on_cleanup(lambda: _delete_table_with_retry(ddb, table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Promote it to a genuine (2019.11.21-native) global table via UpdateTable's
    # ReplicaUpdates, since CreateGlobalTable itself is rejected outright here.
    _create_replica_with_retry(ddb, table_name, region2)
    ctx.on_cleanup(lambda: _swallow(lambda: ddb.update_table(
        TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": region2}}],
    )))
    described_table = _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == region2 and r["ReplicaStatus"] == "ACTIVE"
            for r in table.get("Replicas", [])
        ),
        timeout_s=280,
        interval_s=10,
    )
    regions_present = {r["RegionName"] for r in described_table.get("Replicas", [])} | {region1}
    assert regions_present == {region1, region2}, regions_present

    # The refusal is the contract: DescribeGlobalTable (legacy) does not recognize
    # this real, ACTIVE, cross-region-replicated global table either — the legacy
    # control plane has no path to ever "see" a table promoted the native way.
    real_code, real_message = _error(lambda: ddb.describe_global_table(GlobalTableName=table_name))
    assert real_code == "GlobalTableNotFoundException", (
        f"expected GlobalTableNotFoundException for a real, active global table, got {real_code}"
    )
    expected_real = (
        f"Global table not found: Global table with name: '{table_name}' does not exist."
    )
    assert real_message == expected_real, f"expected message {expected_real!r}, got {real_message!r}"

    # Effect absent via an independent read: ListGlobalTables (the legacy
    # enumeration) does not surface this real, native global table either.
    listed_names = {gt["GlobalTableName"] for gt in ddb.list_global_tables().get("GlobalTables", [])}
    assert table_name not in listed_names, listed_names

    fake_name = ctx.unique_name("sim2real-noglobaltable-")
    fake_code, fake_message = _error(lambda: ddb.describe_global_table(GlobalTableName=fake_name))
    assert fake_code == "GlobalTableNotFoundException", f"expected GlobalTableNotFoundException, got {fake_code}"
    expected_fake = (
        f"Global table not found: Global table with name: '{fake_name}' does not exist."
    )
    assert fake_message == expected_fake, f"expected message {expected_fake!r}, got {fake_message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _delete_table_with_retry(ddb, table_name, *, timeout_s: float = 50, interval_s: float = 5):
    """DeleteTable refuses a table that still lists a replica (ValidationException) and can refuse
    with ResourceInUseException right after a replica delete settles, so wait for the replica
    list to empty, then retry the delete rather than issuing one attempt and leaking the table."""
    replica_deadline = time.monotonic() + 900
    while True:
        try:
            replicas = ddb.describe_table(TableName=table_name)["Table"].get("Replicas")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if not replicas or time.monotonic() >= replica_deadline:
            break
        time.sleep(10)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_replica_with_retry(ddb, table_name, region, *, timeout_s: float = 90, interval_s: float = 5):
    """UpdateTable's ReplicaUpdates "Create" issued right as the source table reaches ACTIVE can
    transiently fail with an AccessDeniedException wrapping an "UnrecognizedClientException"/
    "security token" message while DynamoDB's cross-region replication setup settles — retry for
    a bounded time rather than treating that as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": region}}])
            return
        except ClientError as exc:
            transient = exc.response["Error"]["Code"] == "AccessDeniedException" and (
                "security token" in str(exc).lower()
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
