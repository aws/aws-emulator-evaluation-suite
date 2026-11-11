"""cfn-custom-named-resource-replacement-refused-and-data-survives."""
from __future__ import annotations

import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-custom-named-resource-replacement-refused-and-data-survives"
GROUP = "stack_update"
SERVICES = ["cloudformation", "dynamodb"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
STACK_TIMEOUT_S = 600.0
_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}
_DDB_NOT_FOUND = "ResourceNotFoundException"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An update that would replace a custom-named resource must be refused with the resource and its
    data left intact, while the identical edit to an auto-named twin succeeds."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    template = (DEPLOYMENTS / "named-vs-unnamed-table.yaml").read_text()
    stack = ctx.unique_name("sim2real-cfn-named-")
    name_1 = ctx.unique_name("sim2real-cfn-named-t1-")
    name_2 = ctx.unique_name("sim2real-cfn-named-t2-")
    named_k1, named_k2 = "pk1", "pk2"
    auto_k1, auto_k2 = "ak1", "ak2"
    sentinel = ctx.unique_name("sentinel-")
    payload = ctx.unique_name("payload-")

    cfn.create_stack(
        StackName=stack,
        TemplateBody=template,
        Parameters=_params(NamedTableName=name_1, NamedKey=named_k1, AutoKey=auto_k1),
        Tags=tag,
    )
    # Teardown is LIFO, so these are registered so that DeleteStack runs FIRST and the direct table
    # deletes only mop up whatever the stack failed to remove.
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, name_1))
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, name_2))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack))
    created = _poll_status(
        cfn, stack, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, why="prerequisite create"
    )
    assert created == "CREATE_COMPLETE", f"stack {stack!r}: expected CREATE_COMPLETE, got {created!r}"

    named_pid_0 = _physical_id(cfn, stack, "NamedTable")
    auto_pid_0 = _physical_id(cfn, stack, "AutoTable")
    assert named_pid_0 == name_1, (
        f"the named table's physical id must be the custom name {name_1!r}, got {named_pid_0!r}"
    )
    assert auto_pid_0 != name_1, (
        f"the auto-named table must have a CloudFormation-minted id, got {auto_pid_0!r}"
    )

    # The data whose survival is the real subject: replacement destroys it, refusal preserves it.
    ddb.put_item(TableName=name_1, Item={named_k1: {"S": sentinel}, "payload": {"S": payload}})
    assert _payload(ddb, name_1, named_k1, sentinel) == payload, (
        f"table {name_1!r}: expected the item just written to read back {payload!r}"
    )

    # CloudFormation cannot prove replacement statically from a KeySchema diff, so both tables
    # are classified Conditional and the decision is deferred to execution time.
    changes = _change_set_replacements(
        ctx, cfn, stack, template, NamedTableName=name_1, NamedKey=named_k2, AutoKey=auto_k2
    )
    for logical in ("NamedTable", "AutoTable"):
        assert logical in changes, (
            f"change set must classify {logical!r}; it listed {sorted(changes)!r}"
        )
        assert changes[logical]["replacement"] == "Conditional", (
            f"{logical}: a KeySchema edit must be classified Replacement=Conditional, got "
            f"{changes[logical]['replacement']!r}"
        )
        assert "Conditionally" in changes[logical]["requires_recreation"], (
            f"{logical}: expected a Properties detail with RequiresRecreation='Conditionally', got "
            f"{changes[logical]['requires_recreation']!r}"
        )

    # Positive control: without it, a refusal is indistinguishable from refusing every update.
    control = _update(cfn, stack, template, NamedTableName=name_1, NamedKey=named_k1, AutoKey=auto_k2)
    assert control["outcome"] == "UPDATE_COMPLETE", (
        f"positive control: replacing the AUTO-named table must reach UPDATE_COMPLETE, got "
        f"{control['outcome']!r} / {control['evidence']!r}"
    )
    auto_pid_1 = _physical_id(cfn, stack, "AutoTable")
    assert auto_pid_1 != auto_pid_0, (
        f"the auto-named table must have been REPLACED: physical id was {auto_pid_0!r} and is still "
        f"{auto_pid_1!r}, so nothing was recreated"
    )

    # AWS accepts UpdateStack and then rolls back; there is no synchronous ValidationError.
    refused = _update(cfn, stack, template, NamedTableName=name_1, NamedKey=named_k2, AutoKey=auto_k2)
    assert refused["outcome"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"an update that would replace the custom-named table {name_1!r} must be refused via the "
        f"accepted-then-rolled-back arm, got {refused['outcome']!r} (evidence={refused['evidence']!r})"
    )
    lowered = refused["evidence"].lower()
    assert "custom" in lowered and "replac" in lowered, (
        f"the refusal must say the custom-named resource cannot be replaced; got "
        f"{refused['evidence']!r}"
    )

    named_pid_1 = _physical_id(cfn, stack, "NamedTable")
    assert named_pid_1 == named_pid_0, (
        f"the custom-named table's physical id must be unchanged at {named_pid_0!r} after the refused "
        f"update, got {named_pid_1!r}"
    )
    described = ddb.describe_table(TableName=name_1)["Table"]
    assert described["TableStatus"] == "ACTIVE", (
        f"table {name_1!r} must still be ACTIVE after the refused update, got "
        f"{described['TableStatus']!r}"
    )
    key_names = {k["AttributeName"] for k in described["KeySchema"]}
    assert key_names == {named_k1}, (
        f"table {name_1!r} key schema must still be {{{named_k1!r}}} after the refused update, got "
        f"{sorted(key_names)!r}"
    )
    assert _payload(ddb, name_1, named_k1, sentinel) == payload, (
        f"the item written before the refused update must survive it; table {name_1!r} no longer "
        f"returns {payload!r} for key {sentinel!r}"
    )

    restored = _update(cfn, stack, template, NamedTableName=name_2, NamedKey=named_k2, AutoKey=auto_k2)
    assert restored["outcome"] == "UPDATE_COMPLETE", (
        f"the same KeySchema edit carrying a NEW custom name must succeed, got "
        f"{restored['outcome']!r} / {restored['evidence']!r}"
    )
    named_pid_2 = _physical_id(cfn, stack, "NamedTable")
    assert named_pid_2 == name_2, (
        f"after the renamed replacement the physical id must be {name_2!r}, got {named_pid_2!r}"
    )
    assert {k["AttributeName"] for k in ddb.describe_table(TableName=name_2)["Table"]["KeySchema"]} == {
        named_k2
    }, f"the replacement table {name_2!r} must carry the new key {named_k2!r}"

    old_code, message = _error_code(lambda: ddb.describe_table(TableName=name_1))
    assert old_code == _DDB_NOT_FOUND, (
        f"the replaced table {name_1!r} must be gone: expected {_DDB_NOT_FOUND!r} from DescribeTable, "
        f"got {old_code!r}"
    )
    assert message == f"Requested resource not found: Table: {name_1} not found", (
        f"DescribeTable {_DDB_NOT_FOUND} message: {message!r}"
    )
    old_write, message = _error_code(
        lambda: ddb.put_item(TableName=name_1, Item={named_k1: {"S": sentinel}})
    )
    assert old_write == _DDB_NOT_FOUND, (
        f"a write to the replaced table {name_1!r} must also fail with {_DDB_NOT_FOUND!r}, got "
        f"{old_write!r}"
    )
    assert message == "Requested resource not found", f"PutItem {_DDB_NOT_FOUND} message: {message!r}"


def _params(**kwargs: str) -> list[dict]:
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in kwargs.items()]


def _poll_status(cfn, stack_name: str, terminal: set[str], *, why: str) -> str:
    """Bounded retry with a deadline; RAISES on timeout rather than returning the last value."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach any of {sorted(terminal)!r} within {STACK_TIMEOUT_S}s "
        f"[{why}] (last={last!r})"
    )


def _update(cfn, stack_name: str, template: str, **params: str) -> dict:
    """Issue UpdateStack and return {"outcome", "evidence"} for both the synchronous-error and
    async-rollback arms."""
    try:
        cfn.update_stack(StackName=stack_name, TemplateBody=template, Parameters=_params(**params))
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"outcome": err.get("Code", "<no code>"), "evidence": err.get("Message", "<no message>")}
    status = _poll_status(cfn, stack_name, _UPDATE_TERMINAL, why="update terminal")
    return {"outcome": status, "evidence": _event_reason(cfn, stack_name)}


def _event_reason(cfn, stack_name: str) -> str:
    """The most specific reason in the stack's events: a resource-level *_FAILED reason; the
    stack-level rollback reason names which resource failed but not why."""
    fallback = ""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            reason = event.get("ResourceStatusReason") or ""
            if not reason:
                continue
            is_resource_level = event.get("LogicalResourceId") != stack_name
            if is_resource_level and event.get("ResourceStatus", "").endswith("_FAILED"):
                return reason
            if not fallback:
                fallback = reason
    return fallback or "<no ResourceStatusReason in the event stream>"


def _change_set_replacements(ctx, cfn, stack_name: str, template: str, **params: str) -> dict:
    """CreateChangeSet, wait for it, and return {logical_id: {replacement, requires_recreation}}.
    The change set is deleted, never executed."""
    cs_name = ctx.unique_name("sim2real-cfn-named-cs-")
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=template,
        Parameters=_params(**params),
        ChangeSetType="UPDATE",
    )
    ctx.on_cleanup(lambda: _ignore_missing(lambda: cfn.delete_change_set(StackName=stack_name, ChangeSetName=cs_name)))
    deadline = time.monotonic() + STACK_TIMEOUT_S
    described = None
    while time.monotonic() < deadline:
        described = cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
        if described["Status"] in {"CREATE_COMPLETE", "FAILED"}:
            break
        time.sleep(3.0)
    else:
        raise AssertionError(f"change set {cs_name!r} never left a pending status within {STACK_TIMEOUT_S}s")
    assert described["Status"] == "CREATE_COMPLETE", (
        f"change set {cs_name!r}: expected CREATE_COMPLETE, got {described['Status']!r} "
        f"({described.get('StatusReason')!r})"
    )
    out = {}
    for change in described["Changes"]:
        rc = change["ResourceChange"]
        recreation = {
            d["Target"]["RequiresRecreation"]
            for d in rc.get("Details", [])
            if d.get("Target", {}).get("Attribute") == "Properties"
        }
        out[rc["LogicalResourceId"]] = {
            "replacement": rc.get("Replacement", "<absent>"),
            "requires_recreation": sorted(recreation),
        }
    return out


def _physical_id(cfn, stack_name: str, logical_id: str) -> str:
    detail = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)
    return detail["StackResourceDetail"]["PhysicalResourceId"]


def _payload(ddb, table: str, key_name: str, key_value: str) -> str:
    item = ddb.get_item(
        TableName=table, Key={key_name: {"S": key_value}}, ConsistentRead=True
    ).get("Item")
    assert item is not None, (
        f"table {table!r} returned no item for key {key_name}={key_value!r}; expected the sentinel "
        "written before the refused update"
    )
    return item["payload"]["S"]


def _error_code(fn) -> tuple[str, str]:
    """The botocore Error (Code, Message) raised by fn(); raises if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code", "<no code>"), error.get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _delete_table_if_present(ddb, table: str) -> None:
    """Teardown only, scoped to the two tables this check names."""
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _DDB_NOT_FOUND:
            raise


def _ignore_missing(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"ChangeSetNotFound", "ValidationError"}:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
