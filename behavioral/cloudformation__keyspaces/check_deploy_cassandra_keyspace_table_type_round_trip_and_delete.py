"""deploy-cassandra-keyspace-table-type-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cassandra-keyspace-table-type-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "keyspaces"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "_").replace("-", "_")[:48]


def _keyspace_only(ks_name: str) -> str:
    """The stack after the update that removes the table and the type, leaving their keyspace."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Keyspace": {
                "Type": "AWS::Cassandra::Keyspace",
                "Properties": {"KeyspaceName": ks_name},
            },
        },
        "Outputs": {"KeyspaceRef": {"Value": {"Ref": "Keyspace"}}},
    })


def _template(ks_name: str, table_name: str, type_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Keyspace": {
                "Type": "AWS::Cassandra::Keyspace",
                "Properties": {"KeyspaceName": ks_name},
            },
            "CassandraTable": {
                "Type": "AWS::Cassandra::Table",
                "DependsOn": "Keyspace",
                "Properties": {
                    "KeyspaceName": ks_name,
                    "TableName": table_name,
                    "PartitionKeyColumns": [{"ColumnName": "id", "ColumnType": "TEXT"}],
                    "BillingMode": {"Mode": "ON_DEMAND"},
                },
            },
            "CassandraType": {
                "Type": "AWS::Cassandra::Type",
                "DependsOn": "Keyspace",
                "Properties": {
                    "KeyspaceName": ks_name,
                    "TypeName": type_name,
                    "Fields": [{"FieldName": "field_1", "FieldType": "int"}],
                },
            },
        },
        "Outputs": {
            "KeyspaceRef": {"Value": {"Ref": "Keyspace"}},
            "TableRef": {"Value": {"Ref": "CassandraTable"}},
            "TypeRef": {"Value": {"Ref": "CassandraType"}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack provisions a keyspace, a table in it and a user-defined type in it;
    each reads back through Keyspaces' own API with the template's values; an update removing the
    table and the type deletes each while the keyspace stays, and deleting the stack removes it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_Cassandra.md
    """
    kc = ctx.client("keyspaces")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cassstack-")
    ks_name = _kname(ctx, "sim2realks")
    table_name = _kname(ctx, "sim2realtbl")
    type_name = _kname(ctx, "sim2realtyp")

    stack_id = create_stack(ctx, cfn, stack, _template(ks_name, table_name, type_name))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    assert outputs["KeyspaceRef"] == ks_name, (
        f"Keyspace Ref {outputs['KeyspaceRef']!r} does not equal the keyspace name {ks_name!r}"
    )
    assert outputs["TableRef"] == f"{ks_name}|{table_name}", (
        f"Table Ref {outputs['TableRef']!r}, expected {ks_name}|{table_name}"
    )
    assert outputs["TypeRef"] == f"{ks_name}|{type_name}", (
        f"Type Ref {outputs['TypeRef']!r}, expected {ks_name}|{type_name}"
    )

    keyspace = kc.get_keyspace(keyspaceName=ks_name)
    assert keyspace["keyspaceName"] == ks_name, (
        f"expected keyspaceName {ks_name!r}, Keyspaces reports {keyspace['keyspaceName']!r}"
    )
    assert keyspace["replicationStrategy"] == "SINGLE_REGION", (
        f"expected SINGLE_REGION, Keyspaces reports {keyspace['replicationStrategy']!r}"
    )

    table = kc.get_table(keyspaceName=ks_name, tableName=table_name)
    assert table["status"] == "ACTIVE", (
        f"expected ACTIVE once CREATE_COMPLETE, Keyspaces reports {table['status']!r}"
    )
    assert table["capacitySpecification"]["throughputMode"] == "PAY_PER_REQUEST", (
        f"expected PAY_PER_REQUEST billing, Keyspaces reports "
        f"{table['capacitySpecification']['throughputMode']!r}"
    )
    partition_keys = [c["name"] for c in table["schemaDefinition"]["partitionKeys"]]
    assert partition_keys == ["id"], f"expected partition key ['id'], got {partition_keys!r}"
    columns = [(c["name"], c["type"]) for c in table["schemaDefinition"]["allColumns"]]
    assert columns == [("id", "text")], f"expected the one TEXT column 'id', got {columns!r}"

    udt = kc.get_type(keyspaceName=ks_name, typeName=type_name)
    assert udt["status"] == "ACTIVE", (
        f"expected ACTIVE once CREATE_COMPLETE, Keyspaces reports {udt['status']!r}"
    )
    fields = [(f["name"], f["type"]) for f in udt["fieldDefinitions"]]
    assert fields == [("field_1", "int")], f"expected [('field_1', 'int')], got {fields!r}"

    # Each child's own delete, proven while its keyspace still exists.
    cfn.update_stack(StackName=stack_id, TemplateBody=_keyspace_only(ks_name))
    updated = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert updated == "UPDATE_COMPLETE", f"stack {stack!r} ended {updated!r}, expected UPDATE_COMPLETE"

    table_gone = ("ResourceNotFoundException", f"unconfigured table {table_name}")
    until_raises(lambda: kc.get_table(keyspaceName=ks_name, tableName=table_name), timeout_s=120.0)
    expect_error(lambda: kc.get_table(keyspaceName=ks_name, tableName=table_name), *table_gone)
    type_gone = ("ResourceNotFoundException", f"UDT {type_name} does not exist")
    until_raises(lambda: kc.get_type(keyspaceName=ks_name, typeName=type_name), timeout_s=120.0)
    expect_error(lambda: kc.get_type(keyspaceName=ks_name, typeName=type_name), *type_gone)
    kept = kc.get_keyspace(keyspaceName=ks_name)["keyspaceName"]
    assert kept == ks_name, f"expected keyspace {ks_name!r} to survive the update, Keyspaces reports {kept!r}"

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)
    keyspace_gone = ("ResourceNotFoundException", f"Keyspace {ks_name} does not exist")
    expect_error(lambda: kc.get_keyspace(keyspaceName=ks_name), *keyspace_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
