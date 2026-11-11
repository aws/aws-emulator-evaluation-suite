"""ddbglobal-legacy-2017-global-table-apis-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddbglobal-legacy-2017-global-table-apis-rejected"
GROUP = "global_tables"
SERVICES = ["dynamodb"]

ERR_VALIDATION = "ValidationException"
ERR_GT_NOT_FOUND = "GlobalTableNotFoundException"

#: The withdrawn global-tables version; only it injected aws:rep:* attributes into replicated items.
LEGACY_VERSION = "2017.11.29"


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """CreateGlobalTable and UpdateGlobalTable refuse version 2017.11.29 with ValidationException
    even when its precondition is met, and nothing replicates: no global table, no replicas, each
    region keeps only its own item, and no aws:rep:* attributes appear.
    """
    region_a = ctx.region
    region_b = _derived_second_region(ctx)

    ddb_a = ctx.client("dynamodb")
    ddb_b = ctx.client("dynamodb", region=region_b)

    # ONE name, deliberately: version 2017.11.29 required identically-named tables in every
    # participating region, and the point of this check is that the precondition is met.
    table = ctx.unique_name("sim2real-behav-ddbglobal-legacy-")

    item_a = {"pk": {"S": "shared-key"},
              "origin": {"S": region_a},
              "payload": {"S": "written-in-region-a"},
              "n": {"N": "11"}}
    item_b = {"pk": {"S": "shared-key"},
              "origin": {"S": region_b},
              "payload": {"S": "written-in-region-b"},
              "n": {"N": "22"}}

    for client, region, item in ((ddb_a, region_a, item_a), (ddb_b, region_b, item_b)):
        client.create_table(
            TableName=table,
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
            # The 2017.11.29 precondition, verbatim: streams on, NEW_AND_OLD_IMAGES.
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        # Registered before the next call so neither region's table is stranded by a failing assert.
        ctx.on_cleanup(lambda c=client, t=table: _delete_table_ignore(c, t))
        _wait_table_active(client, table)
        client.put_item(TableName=table, Item=item)

    # POSITIVE CONTROL: both regions are live and serving the data plane, so every absence
    # asserted below is an absence of REPLICATION rather than of a working table.
    got_a = _item(ddb_a, table, "shared-key")
    assert got_a == item_a, f"region {region_a} read back {got_a!r}, wrote {item_a!r}"
    got_b = _item(ddb_b, table, "shared-key")
    assert got_b == item_b, f"region {region_b} read back {got_b!r}, wrote {item_b!r}"

    code, message = _refusal(lambda: ddb_a.create_global_table(
        GlobalTableName=table,
        ReplicationGroup=[{"RegionName": region_a}, {"RegionName": region_b}],
    ))
    assert code == ERR_VALIDATION, (
        f"CreateGlobalTable over two identically-named stream-enabled tables returned {code!r}, "
        f"expected {ERR_VALIDATION!r}; message was {message!r}"
    )
    assert message == "One or more parameter values were invalid: DynamoDB global tables version 2017.11.29 is not supported. We recommend using DynamoDB global tables version 2019.11.21, instead of version 2017.11.29 (Legacy).", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    assert f"{LEGACY_VERSION} is not supported" in message, (
        f"CreateGlobalTable was refused, but not for the withdrawn-version reason: {message!r}"
    )

    code, message = _refusal(lambda: ddb_a.update_global_table(
        GlobalTableName=table,
        ReplicaUpdates=[{"Create": {"RegionName": region_b}}],
    ))
    assert code == ERR_VALIDATION, (
        f"UpdateGlobalTable returned {code!r}, expected {ERR_VALIDATION!r}; "
        f"message was {message!r}"
    )
    assert message == "One or more parameter values were invalid: DynamoDB global tables version 2017.11.29 is not supported. We recommend using DynamoDB global tables version 2019.11.21, instead of version 2017.11.29 (Legacy).", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    assert f"{LEGACY_VERSION} is not supported" in message, (
        f"UpdateGlobalTable was refused, but not for the withdrawn-version reason: {message!r}"
    )

    # EFFECT ABSENT, part 1: no global table was created by the refused calls.
    code, message = _refusal(lambda: ddb_a.describe_global_table(GlobalTableName=table))
    assert code == ERR_GT_NOT_FOUND, (
        f"DescribeGlobalTable returned {code!r} after the refusals, expected "
        f"{ERR_GT_NOT_FOUND!r} -- a refused CreateGlobalTable must leave nothing behind; "
        f"message was {message!r}"
    )
    assert message == f"Global table not found: Global table with name: '{table}' does not exist.", (
        f"expected AWS's exact GlobalTableNotFoundException message, got {message!r}"
    )
    # Scoped to this check's unique name: the account may hold other global tables.
    listed = [n for n in _all_global_table_names(ddb_a) if n == table]
    assert listed == [], f"ListGlobalTables in {region_a} reports {listed!r} after the refusals"

    # EFFECT ABSENT, part 2: no 2019.11.21 replica relationship was created either, in either
    # direction -- a target that "helpfully" upgraded the refused call would show one here.
    for client, region in ((ddb_a, region_a), (ddb_b, region_b)):
        described = client.describe_table(TableName=table)["Table"]
        assert described.get("Replicas", []) == [], (
            f"DescribeTable in {region} reports replicas {described.get('Replicas')!r} after "
            f"CreateGlobalTable was refused"
        )

    # EFFECT ABSENT, part 3: nothing replicated. Each region still holds only its own item, and
    # neither item carries any aws:rep:* attribute -- the metadata version 2017.11.29 documented
    # cannot appear, because the version that injected it is refused.
    final_a = _item(ddb_a, table, "shared-key")
    assert final_a == item_a, (
        f"region {region_a} item changed to {final_a!r} after the refused global-table calls; "
        f"expected the locally written {item_a!r} and no replicated value"
    )
    final_b = _item(ddb_b, table, "shared-key")
    assert final_b == item_b, (
        f"region {region_b} item changed to {final_b!r} after the refused global-table calls; "
        f"expected the locally written {item_b!r} and no replicated value"
    )
    injected = sorted(k for k in list(final_a) + list(final_b) if k.startswith("aws:"))
    assert injected == [], (
        f"items carry AWS-injected replication metadata {injected!r}; version {LEGACY_VERSION} "
        f"is the only version that ever added aws:rep:* attributes and real AWS refuses it"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *,
                timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _wait_table_active(ddb, table: str, timeout_s: float = 180) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3,
    )


def _item(ddb, table: str, key: str) -> dict | None:
    """Strongly consistent GetItem, so a stale read cannot decide a replication assertion."""
    return ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")


def _refusal(fn: Callable[[], Any]) -> tuple[str, str]:
    """(error code, message) for a call real AWS must refuse; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _all_global_table_names(ddb) -> list[str]:
    """All global table names, following ListGlobalTables pagination."""
    names: list[str] = []
    kwargs: dict[str, Any] = {}
    while True:
        page = ddb.list_global_tables(**kwargs)
        names.extend(g["GlobalTableName"] for g in page.get("GlobalTables", []))
        last = page.get("LastEvaluatedGlobalTableName")
        if not last:
            return names
        kwargs = {"ExclusiveStartGlobalTableName": last}


def _derived_second_region(ctx) -> str:
    """us-east-1, or us-west-2 when ctx.region is us-east-1; both are enabled in every account."""
    return "us-east-1" if ctx.region != "us-east-1" else "us-west-2"


def _delete_table_ignore(ddb, table: str) -> None:
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
