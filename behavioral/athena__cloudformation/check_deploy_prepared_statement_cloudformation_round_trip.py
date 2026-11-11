"""deploy-prepared-statement-cloudformation-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-prepared-statement-cloudformation-round-trip"
GROUP = "deploy"
SERVICES = ["athena", "cloudformation"]

# ---- CloudFormation helpers ----

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

_DESCRIPTION = "sim2real behavioral fidelity check prepared statement"


def _template(work_group: str, statement: str, with_statement: bool = True) -> str:
    resources = {
        "WG": {"Type": "AWS::Athena::WorkGroup",
               "Properties": {"Name": work_group, "RecursiveDeleteOption": True}},
    }
    outputs = {"WorkGroupRef": {"Value": {"Ref": "WG"}}}
    if with_statement:
        resources["PS"] = {
            "Type": "AWS::Athena::PreparedStatement",
            "Properties": {
                "StatementName": statement,
                "WorkGroup": {"Ref": "WG"},
                "QueryStatement": "SELECT 1 AS answer",
                "Description": _DESCRIPTION,
            },
        }
        outputs["PreparedStatementRef"] = {"Value": {"Ref": "PS"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _all(fn, key: str, **kw) -> list:
    """Every item under ``key`` across the NextToken pages of ``fn``."""
    found = []
    while True:
        page = fn(**kw)
        found += page[key]
        if not page.get("NextToken"):
            return found
        kw["NextToken"] = page["NextToken"]


def _statements(athena, work_group: str) -> list[str]:
    return sorted(s["StatementName"] for s in _all(
        athena.list_prepared_statements, "PreparedStatements", WorkGroup=work_group))


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Athena PreparedStatement reads back through Athena, then deletes.

    Its Ref is the name|workgroup of the one statement listed, with the templated query; an update
    dropping it empties the live workgroup, and the stack delete removes the workgroup.
    """
    cfn = ctx.client("cloudformation")
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-behav-wg-")
    statement = ctx.unique_name("sim2real_behav_ps_")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-stack-"),
                            _template(wg_name, statement))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    groups = [g["Name"] for g in _all(athena.list_work_groups, "WorkGroups") if g["Name"] == wg_name]
    assert groups == [out["WorkGroupRef"]], f"workgroups named {wg_name!r}: {groups!r}"
    assert _statements(athena, wg_name) == [statement], f"statements of {wg_name!r}"
    assert out["PreparedStatementRef"] == f"{statement}|{wg_name}", (
        f"PreparedStatement Ref {out['PreparedStatementRef']!r}"
    )
    ps = athena.get_prepared_statement(StatementName=statement, WorkGroup=wg_name)[
        "PreparedStatement"]
    got = (ps["StatementName"], ps["WorkGroupName"], ps["QueryStatement"], ps.get("Description"))
    want = (statement, wg_name, "SELECT 1 AS answer", _DESCRIPTION)
    assert got == want, f"statement reads {got!r}, expected {want!r}"
    created = athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]["CreationTime"]

    # Child before parent: the update drops only the statement; the live workgroup lists none.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(wg_name, statement,
                                                                with_statement=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"statement-removing update ended {status!r}"
    live = athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]
    got = (live["Name"], live["CreationTime"])
    assert got == (wg_name, created), (
        f"workgroup after the update reads {got!r}, expected the same {(wg_name, created)!r}"
    )
    assert _statements(athena, wg_name) == [], f"statements of {wg_name!r} after the update"

    delete_stack(cfn, stack_id)
    refused = ("InvalidRequestException", "WorkGroup is not found.")
    expect_error(
        lambda: athena.get_prepared_statement(StatementName=statement, WorkGroup=wg_name), *refused
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
