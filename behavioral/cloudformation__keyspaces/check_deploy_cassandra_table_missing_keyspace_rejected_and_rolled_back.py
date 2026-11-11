"""deploy-cassandra-table-missing-keyspace-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cassandra-table-missing-keyspace-rejected-and-rolled-back"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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


def _table_only_template(ks_name: str, table_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "CassandraTable": {
                "Type": "AWS::Cassandra::Table",
                "Properties": {
                    "KeyspaceName": ks_name,
                    "TableName": table_name,
                    "PartitionKeyColumns": [{"ColumnName": "id", "ColumnType": "TEXT"}],
                    "BillingMode": {"Mode": "ON_DEMAND"},
                },
            },
        },
        "Outputs": {"TableRef": {"Value": {"Ref": "CassandraTable"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Cassandra::Table naming a keyspace that was never created is
    rejected by Keyspaces, the stack rolls back and creates no table; the identical template
    against a keyspace that does exist succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cassandra-table.html
    """
    kc = ctx.client("keyspaces")
    cfn = ctx.client("cloudformation")
    missing_ks = _kname(ctx, "sim2realmissingks")
    table_name = _kname(ctx, "sim2realtbl")

    stack = ctx.unique_name("sim2real-cassmissks-")
    stack_id = create_stack(ctx, cfn, stack, _table_only_template(missing_ks, table_name))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"a table naming the never-created keyspace {missing_ks!r} ended "
        f"{status!r}, expected 'ROLLBACK_COMPLETE'"
    )

    events = stack_events(cfn, stack_id)
    failed = [e for e in events if e.get("ResourceStatus") == "CREATE_FAILED"]
    assert [e["LogicalResourceId"] for e in failed] == ["CassandraTable"], (
        f"expected exactly the table to fail creation; CREATE_FAILED events were "
        f"{[(e['LogicalResourceId'], e.get('ResourceStatusReason')) for e in failed]!r}"
    )
    got = handler_reason(failed[0].get("ResourceStatusReason"), ctx.account)
    want = (f"Keyspace {missing_ks} does not exist", "InvalidRequest")
    assert got == want, f"CREATE_FAILED reason: expected {want!r}, got {got!r}"

    # Effect-absent: the failed table did not make Keyspaces create its keyspace on the way.
    missing_gone = ("ResourceNotFoundException", f"Keyspace {missing_ks} does not exist")
    expect_error(lambda: kc.get_keyspace(keyspaceName=missing_ks), *missing_gone)

    delete_stack(cfn, stack_id)

    # Positive control: the identical template succeeds once the keyspace genuinely exists.
    real_ks = _kname(ctx, "sim2realrealks")
    # The cleanup goes first (it treats only ResourceNotFoundException as gone), and the
    # keyspace carries the sim2real tag.
    ctx.on_cleanup(lambda: _delete_keyspace_eventually(kc, real_ks))
    kc.create_keyspace(keyspaceName=real_ks, tags=[{"key": "sim2real", "value": real_ks}])
    _wait_keyspace_visible(kc, real_ks)

    control_table_name = _kname(ctx, "sim2realtbl")
    control_stack = ctx.unique_name("sim2real-cassrealks-")
    control_id = create_stack(ctx, cfn, control_stack,
                              _table_only_template(real_ks, control_table_name))
    status = wait_stack(cfn, control_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"the same template against the real keyspace {real_ks!r} ended "
        f"{status!r}: {decisive_rows(stack_events(cfn, control_id))!r}"
    )
    control_ref = stack_outputs(cfn, control_id)["TableRef"]
    assert control_ref == f"{real_ks}|{control_table_name}", (
        f"Table Ref {control_ref!r}, expected {real_ks}|{control_table_name}"
    )
    control_table = kc.get_table(keyspaceName=real_ks, tableName=control_table_name)
    assert control_table["status"] == "ACTIVE", (
        f"expected ACTIVE once CREATE_COMPLETE, Keyspaces reports {control_table['status']!r}"
    )
    assert control_table["capacitySpecification"]["throughputMode"] == "PAY_PER_REQUEST", (
        f"expected PAY_PER_REQUEST billing, Keyspaces reports "
        f"{control_table['capacitySpecification']['throughputMode']!r}"
    )
    partition_keys = [c["name"] for c in control_table["schemaDefinition"]["partitionKeys"]]
    assert partition_keys == ["id"], f"expected partition key ['id'], got {partition_keys!r}"
    columns = [(c["name"], c["type"]) for c in control_table["schemaDefinition"]["allColumns"]]
    assert columns == [("id", "text")], f"expected the one TEXT column 'id', got {columns!r}"

    delete_stack(cfn, control_id)


def _wait_keyspace_visible(kc, ks_name: str, timeout_s: float = 90.0) -> None:
    """CreateKeyspace is asynchronous: GetKeyspace answers ResourceNotFoundException for a beat."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.get_keyspace(keyspaceName=ks_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _delete_keyspace_eventually(kc, ks_name: str, timeout_s: float = 45.0) -> None:
    """DeleteKeyspace answers ConflictException while a table of its own is still finishing a
    delete; retry only that condition, and tolerate not-found."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.delete_keyspace(keyspaceName=ks_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
