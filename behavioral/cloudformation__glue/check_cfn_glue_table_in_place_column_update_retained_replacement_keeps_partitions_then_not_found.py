"""cfn-glue-table-in-place-column-update-retained-replacement-keeps-partitions-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-glue-table-in-place-column-update-retained-replacement-keeps-partitions-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_READ_CAP_S = 30.0
#: Every teardown waits to one deadline, set by the first to run, inside the cleanup budget.
_TEARDOWN_S = 1700.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_BASE_COLUMNS = [{"Name": "id", "Type": "string"}, {"Name": "amount", "Type": "int"}]
_EXTRA_COLUMN = {"Name": "note", "Type": "string"}
_PARTITION_KEYS = [{"Name": "dt", "Type": "string"}]
_INPUT_FORMAT = "org.apache.hadoop.mapred.TextInputFormat"
_OUTPUT_FORMAT = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
_SERDE = "org.openx.data.jsonserde.JsonSerDe"

#: Glue's refusal of a table CloudFormation deleted from an existing database.
_NOT_FOUND_CODE = "EntityNotFoundException"
_NOT_FOUND_MESSAGE = "Entity Not Found"
_DATABASE_NOT_FOUND = "EntityNotFoundException"


def _location(table: str) -> str:
    # A table's location is metadata here: nothing reads it.
    return f"s3://sim2real-unread-location/{table}/"


def _storage(table: str, columns: list[dict]) -> dict:
    return {
        "Columns": columns,
        "Location": _location(table),
        "InputFormat": _INPUT_FORMAT,
        "OutputFormat": _OUTPUT_FORMAT,
        "SerdeInfo": {"SerializationLibrary": _SERDE},
    }


def _template(database: str, table: str, columns: list[dict], description: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Table": {
                    "Type": "AWS::Glue::Table",
                    # TableInput.Name is create-only, so changing it replaces the table.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "CatalogId": {"Ref": "AWS::AccountId"},
                        "DatabaseName": database,
                        "TableInput": {
                            "Name": table,
                            "Description": description,
                            "TableType": "EXTERNAL_TABLE",
                            "Parameters": {"classification": "json"},
                            "PartitionKeys": _PARTITION_KEYS,
                            "StorageDescriptor": _storage(table, columns),
                        },
                    },
                },
            },
            "Outputs": {"TableName": {"Value": {"Ref": "Table"}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation Glue table reads back as templated, updates in place and survives replacing.

    It holds a partition; an added column keeps the table and partition, a TableInput.Name change
    under UpdateReplacePolicy Retain keeps the old table with it; delete: EntityNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-table.html
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    database = ctx.unique_name("sim2real_cfngtb_db_").replace("-", "_")
    first = ctx.unique_name("sim2real_cfngtb_a_").replace("-", "_")
    second = ctx.unique_name("sim2real_cfngtb_b_").replace("-", "_")
    stack_name = ctx.unique_name("sim2real-cfngtb-stack-")
    ref = {"stack": stack_name}
    teardown: dict = {}
    wide = [*_BASE_COLUMNS, _EXTRA_COLUMN]

    # The database belongs to the check, so the retained table goes with it.
    ctx.on_cleanup(lambda: _delete_database(glue, database))
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref, teardown))

    # ---- 1. create: CloudFormation's view, Glue's view, and a partition round trip
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(database, first, _BASE_COLUMNS, "first"),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Table"] == first, (
        f"the table's physical id must be its name {first!r}"
    )
    assert _outputs(stack) == {"TableName": first}, f"Ref outputs {_outputs(stack)!r}"
    _eventually(
        ctx,
        _READ_CAP_S,
        lambda: _assert_table(ctx, glue, database, first, _BASE_COLUMNS, "first"),
    )
    _add_partition(glue, database, first, "2026-01-01", _BASE_COLUMNS)
    _eventually(ctx, _READ_CAP_S, lambda: _assert_partitions(glue, database, first, ["2026-01-01"]))

    # ---- 2. in-place: an added column and a new Description, the same table and partition
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(database, first, wide, "second"),
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Table"] == first, "an in-place update keeps the table"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Table"), first, "Table")
    _eventually(ctx, _READ_CAP_S, lambda: _assert_table(ctx, glue, database, first, wide, "second"))
    _assert_partitions(glue, database, first, ["2026-01-01"])

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new table, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(database, second, wide, "second"),
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Table"] == second, (
        f"the replacement's physical id must be its name {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Table"), first, second, "Table"
    )
    assert _outputs(stack) == {"TableName": second}, f"Ref after replacement {_outputs(stack)!r}"
    _eventually(
        ctx, _READ_CAP_S, lambda: _assert_table(ctx, glue, database, second, wide, "second")
    )
    _add_partition(glue, database, second, "2026-01-02", wide)
    _eventually(
        ctx, _READ_CAP_S, lambda: _assert_partitions(glue, database, second, ["2026-01-02"])
    )
    _assert_table(ctx, glue, database, first, wide, "second")
    _assert_partitions(glue, database, first, ["2026-01-01"])

    # ---- 4. delete: Glue no longer knows the stack's table; the retained one keeps its partition
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: glue.get_table(DatabaseName=database, Name=second),
        _NOT_FOUND_CODE,
        f"table {database}.{second}",
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE)
    assert got == want, f"GetTable after the stack delete answered {got!r}"
    _assert_partitions(glue, database, first, ["2026-01-01"])


def _assert_table(ctx, glue, database: str, name: str, columns: list[dict], description: str):
    """GetTable reports the template's table, columns included, exactly."""
    table = glue.get_table(DatabaseName=database, Name=name)["Table"]
    keys = ("Name", "DatabaseName", "CatalogId", "Description", "TableType", "Parameters")
    got = {k: table.get(k) for k in keys}
    got["PartitionKeys"] = table.get("PartitionKeys")
    storage = table.get("StorageDescriptor", {})
    got["Storage"] = {
        "Columns": storage.get("Columns"),
        "Location": storage.get("Location"),
        "InputFormat": storage.get("InputFormat"),
        "OutputFormat": storage.get("OutputFormat"),
        "SerializationLibrary": storage.get("SerdeInfo", {}).get("SerializationLibrary"),
    }
    want = {
        "Name": name,
        "DatabaseName": database,
        "CatalogId": ctx.account,
        "Description": description,
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {"classification": "json"},
        "PartitionKeys": _PARTITION_KEYS,
        "Storage": {
            "Columns": columns,
            "Location": _location(name),
            "InputFormat": _INPUT_FORMAT,
            "OutputFormat": _OUTPUT_FORMAT,
            "SerializationLibrary": _SERDE,
        },
    }
    assert got == want, f"GetTable {database}.{name}: {got!r}, expected {want!r}"


def _add_partition(glue, database: str, table: str, day: str, columns: list[dict]) -> None:
    storage = _storage(table, columns)
    storage["Location"] = f"{_location(table)}dt={day}/"
    glue.create_partition(
        DatabaseName=database,
        TableName=table,
        PartitionInput={"Values": [day], "StorageDescriptor": storage},
    )


def _assert_partitions(glue, database: str, table: str, days: list[str]) -> None:
    pages = glue.get_paginator("get_partitions").paginate(DatabaseName=database, TableName=table)
    got = sorted(
        (p["Values"], p["StorageDescriptor"]["Location"])
        for page in pages
        for p in page["Partitions"]
    )
    want = [([day], f"{_location(table)}dt={day}/") for day in days]
    assert got == want, f"partitions of {database}.{table}: {got!r}, expected {want!r}"


def _delete_database(glue, name: str) -> None:
    try:
        glue.delete_database(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _DATABASE_NOT_FOUND:
            raise


def _eventually(ctx, cap_s, probe):
    """Run *probe* until it stops failing an assert; past the cap its last assert fails."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        try:
            return probe()
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"run budget ended before a read converged: {exc}") from None
                raise
        time.sleep(_POLL_S)


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status.

    A teardown wait ends at the deadline every teardown shares.
    """
    timeout = _budget_s(ctx, _STACK_CAP_S) if teardown is None else _teardown_left(teardown)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if teardown is None and _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, teardown=teardown), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict, teardown: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"], teardown=teardown)
    _delete_stack(ctx, cfn, stack["StackId"], teardown=teardown)


def _teardown_left(teardown: dict) -> float:
    """Seconds, at least 1, to the deadline every teardown shares; the first to ask fixes it."""
    deadline = teardown.setdefault("deadline", time.monotonic() + _TEARDOWN_S)
    return max(1.0, deadline - time.monotonic())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
