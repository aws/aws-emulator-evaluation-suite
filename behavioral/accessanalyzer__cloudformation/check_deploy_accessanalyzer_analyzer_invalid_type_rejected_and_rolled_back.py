"""deploy-accessanalyzer-analyzer-invalid-type-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-accessanalyzer-analyzer-invalid-type-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["accessanalyzer", "cloudformation"]

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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


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

_ANALYZER_NOT_FOUND = ("ResourceNotFoundException", "Analyzer not found")
_REJECTED = (
    '[instance value ("NOT_A_REAL_TYPE") not found in enum (possible values: '
    '["ACCOUNT","ORGANIZATION","ACCOUNT_UNUSED_ACCESS","ORGANIZATION_UNUSED_ACCESS",'
    '"ACCOUNT_INTERNAL_ACCESS","ORGANIZATION_INTERNAL_ACCESS","ACCOUNT_INTERNAL_ACCESS_V2",'
    '"ORGANIZATION_INTERNAL_ACCESS_V2"])] (Service: AccessAnalyzer, Status Code: 400, '
    "Request ID: <id>) (SDK Attempt Count: <n>)"
)


def _template(analyzer_name, analyzer_type):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Analyzer": {
                "Type": "AWS::AccessAnalyzer::Analyzer",
                "Properties": {"AnalyzerName": analyzer_name, "Type": analyzer_type},
            },
        },
    })


def _own_analyzer(aa, name):
    """The ACCOUNT-type analyzer named ``name``, from an independent paginated list read."""
    return [a for a in paginate(aa, "list_analyzers", "analyzers", type="ACCOUNT")
            if a["name"] == name]


@tags("axis:rejection", "concern:deploy", "concern:negative-classes", "plane:control",
      "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """A CloudFormation Access Analyzer with an invalid Type is refused and rolls back.

    The handler rejects an unrecognized Type and no analyzer exists, while the same template
    with Type ACCOUNT deploys.
    """
    cf = ctx.client("cloudformation")
    aa = ctx.client("accessanalyzer")
    good_analyzer = ctx.unique_name("sim2real-cfnaa-type-good-")
    bad_analyzer = ctx.unique_name("sim2real-cfnaa-type-bad-")

    # One ACCOUNT analyzer per account and Region: the control can create it only in a clean slot.
    prior = [a["name"] for a in paginate(aa, "list_analyzers", "analyzers", type="ACCOUNT")]
    assert prior == [], f"precondition: {len(prior)} ACCOUNT analyzer(s) already hold the slot"

    # Positive control: same template, the one property given a VALID value (never dropped).
    # Both stacks deploy at once so the run stays well inside the per-check budget.
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnaa-type-goodstack-"),
                           _template(good_analyzer, "ACCOUNT"))
    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnaa-type-badstack-"),
                          _template(bad_analyzer, "NOT_A_REAL_TYPE"))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    listed = _own_analyzer(aa, good_analyzer)
    assert len(listed) == 1, f"ListAnalyzers(type=ACCOUNT) found {listed!r} for the control"
    got = aa.get_analyzer(analyzerName=good_analyzer)["analyzer"]
    assert (got["name"], got["type"], got["status"]) == (good_analyzer, "ACCOUNT", "ACTIVE"), (
        f"control analyzer reads {(got['name'], got['type'], got['status'])!r}"
    )

    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cf, bad_id), "Analyzer")
    got_reason = masked(reason, ctx.account, bad_analyzer)
    assert got_reason == _REJECTED, f"handler reason {got_reason!r}, expected {_REJECTED!r}"

    # Rollback absence through Access Analyzer, by the name it would have, BEFORE this check
    # deletes either stack.
    listed = _own_analyzer(aa, bad_analyzer)
    assert listed == [], f"the rolled-back analyzer is listed: {listed!r}"
    expect_error(lambda: aa.get_analyzer(analyzerName=bad_analyzer), *_ANALYZER_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
