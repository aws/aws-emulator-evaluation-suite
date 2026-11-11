"""global-table-settings-update."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-table-settings-update"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]


def _poll_until(
    probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _other_region(region):
    # These are concrete, real AWS region names, not a stand-in for a genuinely global or
    # region-pinned resource: a global-table replica MUST live in some second real region, and
    # there is no way to derive "some other region" from ctx alone, so a short literal list of
    # known-good regions (excluding ctx.region) is the only way to pick one.
    for r in ("us-east-1", "us-west-2", "us-east-2"):
        if r != region:
            return r
    return "us-east-1"


def _teardown(ddb, name, second_region):
    # Teardown of a global table is slow for reasons AWS owns, not this check: after UpdateTable's
    # ReplicaUpdates "Delete" is issued, the replica takes ~30-180s to disappear from
    # describe_table's Replicas[], and DeleteTable rejects the table for that whole window with
    # ValidationException "Replica cannot be deleted because it has acted as a source region for new
    # replica(s) being added to the table in the last 24 hours" (the wording overstates it -- it
    # clears once the replica is actually gone, not after 24h). So "issue the Delete, then call
    # delete_table once" leaks the table every run.
    try:
        ddb.update_table(
            TableName=name, ReplicaUpdates=[{"Delete": {"RegionName": second_region}}]
        )
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise

    def _replica_gone():
        try:
            replicas = ddb.describe_table(TableName=name)["Table"].get("Replicas") or []
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ResourceNotFoundException",
                "TableNotFoundException",
            ):
                raise
            return True
        return not replicas

    def _try_delete():
        try:
            ddb.delete_table(TableName=name)
            return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "ResourceNotFoundException":
                return True  # already gone
            retryable = code == "ResourceInUseException" or (
                code == "ValidationException" and "acted as a source region" in message
            )
            if not retryable:
                raise
            return False

    # 240 s, within the suite's cleanup budget: the replica needs up to ~180 s to disappear
    # before DeleteTable accepts the table's delete.
    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline:
        if _replica_gone() and _try_delete():
            return
        time.sleep(3.0)
    _try_delete()  # one last honest attempt; if this also raises, it is reported truthfully


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


def _wait_table_active(ddb, name, timeout_s=90):
    return _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"],
        lambda t: (
            t["TableStatus"] == "ACTIVE"
            and all(
                idx.get("IndexStatus", "ACTIVE") == "ACTIVE"
                for idx in t.get("GlobalSecondaryIndexes", [])
            )
            and all(
                r.get("ReplicaStatus", "ACTIVE") == "ACTIVE"
                for r in t.get("Replicas", [])
            )
        ),
        timeout_s=timeout_s,
        interval_s=1.0,
        description=f"table {name} ACTIVE",
    )


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The legacy (2017.11.29) UpdateGlobalTableSettings and DescribeGlobalTableSettings both refuse
    GlobalTableNotFoundException, both for a two-Region global table built the 2019.11.21 way
    (UpdateTable ReplicaUpdates), which the legacy API never tracks, and for a name never a table."""
    ddb = ctx.client("dynamodb")
    second_region = _other_region(ctx.region)

    name = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # Fallback net: if the replica-create call below never runs (or raises before its own
    # combined teardown is registered), this still reclaims the bare table. Once the replica
    # exists, _teardown below supersedes this -- it removes the replica first, then deletes
    # the table itself, so this net tolerates a table that is already gone or being deleted.
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.update_table(
        TableName=name, ReplicaUpdates=[{"Create": {"RegionName": second_region}}]
    )
    ctx.on_cleanup(lambda: _teardown(ddb, name, second_region))
    _wait_table_active(ddb, name, timeout_s=240)

    expected_message = f"Global table with name: '{name}' does not exist."
    describe_code, describe_message = _error_code_and_message(
        lambda: ddb.describe_global_table_settings(GlobalTableName=name)
    )
    assert describe_code == "GlobalTableNotFoundException", (
        f"expected GlobalTableNotFoundException, got {describe_code}"
    )
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    update_code, update_message = _error_code_and_message(
        lambda: ddb.update_global_table_settings(
            GlobalTableName=name,
            ReplicaSettingsUpdate=[
                {
                    "RegionName": second_region,
                    "ReplicaTableClass": "STANDARD_INFREQUENT_ACCESS",
                }
            ],
        )
    )
    assert update_code == "GlobalTableNotFoundException", (
        f"expected GlobalTableNotFoundException, got {update_code}"
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )

    # Same rejection for a name that was NEVER a real table either.
    bogus_name = ctx.unique_name("sim2real-behav-no-such-global-table-")
    bogus_code, bogus_message = _error_code_and_message(
        lambda: ddb.describe_global_table_settings(GlobalTableName=bogus_name)
    )
    assert bogus_code == "GlobalTableNotFoundException", bogus_code
    expected_bogus = f"Global table with name: '{bogus_name}' does not exist."
    assert bogus_message == expected_bogus, f"expected message {expected_bogus!r}, got {bogus_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
