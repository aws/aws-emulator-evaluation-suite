"""deploy-prepared-statement-cloudformation-missing-workgroup-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-prepared-statement-cloudformation-missing-workgroup-rejected"
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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


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


# ---- Check-specific: the template, then run(). ----

#: CloudFormation's generic handler reason: it names neither the workgroup nor the cause, so the
#: twin control (only the WorkGroup differs) is what pins the refusal to the missing workgroup.
_REJECTED = ("Error occurred during operation 'AWS::Athena::PreparedStatement'.",
             "GeneralServiceException")


def _template(work_group: str, statement: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "PS": {
                "Type": "AWS::Athena::PreparedStatement",
                "Properties": {
                    "StatementName": statement,
                    "WorkGroup": work_group,
                    "QueryStatement": "SELECT 1 AS answer",
                },
            },
        },
    })


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


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Athena PreparedStatement naming a WorkGroup that does not exist fails.

    The handler refuses it and the stack rolls back, while the same template naming an existing
    workgroup creates the statement that workgroup then lists alone.
    """
    cfn = ctx.client("cloudformation")
    athena = ctx.client("athena")
    work_group = ctx.unique_name("sim2real-behav-wg-")
    good_statement = ctx.unique_name("sim2real_behav_ps_")
    bad_statement = ctx.unique_name("sim2real_behav_ps_")

    athena.create_work_group(Name=work_group, Tags=[{"Key": "sim2real", "Value": work_group}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=work_group,
                                                    RecursiveDeleteOption=True))

    # Positive control: the same template naming the existing workgroup.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-stack-"),
                           _template(work_group, good_statement))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    ps = athena.get_prepared_statement(StatementName=good_statement, WorkGroup=work_group)[
        "PreparedStatement"]
    got = (ps["StatementName"], ps["WorkGroupName"], ps["QueryStatement"])
    assert got == (good_statement, work_group, "SELECT 1 AS answer"), f"control reads {got!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-stack-"),
                          _template(ctx.unique_name("sim2real-behav-missing-wg-"), bad_statement))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    events = stack_events(cfn, bad_id)
    got = handler_reason(failed_reason(events, "PS"), ctx.account)
    assert got == _REJECTED, f"PS reason {got!r}, expected {_REJECTED!r}"
    # The refused create minted no statement: its CREATE_FAILED row carries no physical id.
    physical = [e.get("PhysicalResourceId", "") for e in events
                if e["LogicalResourceId"] == "PS" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert physical == [""], f"PS CREATE_FAILED physical ids {physical!r}, expected ['']"

    # Control read: the real workgroup still lists exactly the control statement.
    listed = _statements(athena, work_group)
    assert listed == [good_statement], f"statements of {work_group!r}: {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
