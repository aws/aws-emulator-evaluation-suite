"""global-table-replica-already-exists-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "global-table-replica-already-exists-rejected"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable ReplicaUpdates Create for a region that is already a replica of the global table raises
    ValidationException with the exact message and leaves the replica set unchanged.
    """
    ddb = ctx.client("dynamodb")
    region1 = ctx.region
    region2 = _secondary_region(region1)
    global_name = ctx.unique_name("sim2real-behav-gtr-")

    ddb.create_table(
        TableName=global_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, global_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=global_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )

    # Accounts/regions that must use global tables version 2019.11.21 reject the legacy
    # CreateGlobalTable call outright ("DynamoDB global tables version 2019.11.21 must be
    # used to create new global tables"); establish the global table the 2019.11.21-native
    # way instead, via UpdateTable's ReplicaUpdates from the original region's client (no
    # second-region client required — DynamoDB creates the replica table remotely).
    #
    # A ReplicaUpdates "Create" issued the instant the source table (with a freshly-enabled
    # stream) reaches ACTIVE can be transiently rejected with an AccessDeniedException wrapping
    # an "UnrecognizedClientException"/"security token" message while DynamoDB's cross-region
    # replication setup settles — retry instead of treating that as a hard failure.
    _create_replica_with_retry(ddb, global_name, region2)
    ctx.on_cleanup(lambda: _safe_remove_replica(ddb, global_name, region2))

    # IMPORTANT: legacy DescribeGlobalTable/UpdateGlobalTable (2017.11.29-only) do NOT recognize a
    # table made global via UpdateTable's ReplicaUpdates (the 2019.11.21-native path used above,
    # required on accounts where CreateGlobalTable itself is rejected) — they 404 with
    # GlobalTableNotFoundException PERMANENTLY for such a table, not transiently. A poll that
    # tolerates that error as "not ready yet" therefore never converges and just burns the whole
    # check budget. The 2019.11.21-native way to observe AND mutate replica state is DescribeTable
    # (Table.Replicas[].ReplicaStatus) / UpdateTable (ReplicaUpdates) — used below.
    described = _poll_until(
        lambda: ddb.describe_table(TableName=global_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == region2 and r["ReplicaStatus"] == "ACTIVE"
            for r in table.get("Replicas", [])
        ),
        timeout_s=280,
        interval_s=10,
    )
    regions_present = {r["RegionName"] for r in described.get("Replicas", [])} | {region1}
    assert regions_present == {region1, region2}, (regions_present, {region1, region2})

    code, message = _error_code_and_message(
        lambda: ddb.update_table(
            TableName=global_name,
            ReplicaUpdates=[{"Create": {"RegionName": region2}}],
        )
    )
    # Real AWS rejects re-"Create"-ing an ALREADY-present replica region with a generic
    # ValidationException (not the more specific ReplicaAlreadyExistsException, which DynamoDB
    # reserves for the legacy 2017.11.29 CreateGlobalTable/UpdateGlobalTable surface) — assert the
    # code AND its exact message, so this verifies the rejection is about the duplicate replica
    # and not some unrelated validation failure.
    assert code == "ValidationException", (code, message)
    # AWS's own wording, including "a the" and the typographic quotes around the name.
    expected_message = (
        f"Failed to create a the new replica of table with name: \u2018{global_name}\u2019 "
        "because one or more replicas already existed as tables."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The replication group must remain exactly as it was before the rejected update.
    unchanged = ddb.describe_table(TableName=global_name)["Table"]
    unchanged_regions = {r["RegionName"] for r in unchanged.get("Replicas", [])} | {region1}
    assert unchanged_regions == {region1, region2}, (unchanged_regions, {region1, region2})


def _secondary_region(primary_region: str) -> str:
    """A region distinct from the primary, for a global table replica."""
    return "us-west-2" if primary_region != "us-west-2" else "us-east-1"


def _create_replica_with_retry(
    ddb: Any, table_name: str, region: str, *, timeout_s: float = 90, interval_s: float = 5
) -> None:
    """UpdateTable's ReplicaUpdates "Create" issued right as the source table reaches ACTIVE can
    transiently fail with an AccessDeniedException wrapping an "UnrecognizedClientException"/
    "security token" message while DynamoDB's cross-region replication setup settles — retry for
    a bounded time rather than treating that as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": region}}])
            return
        except Exception as exc:  # noqa: BLE001
            transient = _error_code_from_exc(exc) == "AccessDeniedException" and "security token" in str(
                exc
            ).lower()
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_remove_replica(ddb: Any, global_name: str, region: str) -> None:
    try:
        ddb.update_table(
            TableName=global_name, ReplicaUpdates=[{"Delete": {"RegionName": region}}]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise
        return
    try:
        _poll_until(
            lambda: {
                r["RegionName"]
                for r in ddb.describe_table(TableName=global_name)["Table"].get("Replicas", [])
            },
            lambda regions: region not in regions,
            timeout_s=120,
            interval_s=10,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _error_code_and_message(fn: Callable[[], Any]) -> tuple[str | None, str | None]:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(
        "real DynamoDB rejects re-adding a replica region that is already present, but the "
        "UpdateTable call SUCCEEDED"
    )


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
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

