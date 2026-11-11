"""deploy-inspectorv2-filter-and-scan-config-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-inspectorv2-filter-and-scan-config-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "inspector2"]

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



def _filter_resource(filter_name, action):
    """A Filter matching only findings titled ``filter_name``: it suppresses nothing real."""
    return {
        "Type": "AWS::InspectorV2::Filter",
        "Properties": {
            "Name": filter_name,
            "Description": "sim2real filter",
            "FilterCriteria": {"Title": [{"Comparison": "EQUALS", "Value": filter_name}]},
            "FilterAction": action,
            "Tags": {"sim2real-insp": filter_name},
        },
    }


def _filters(insp, name):
    """Every filter Inspector2 lists under exactly ``name`` (all pages)."""
    return [f for f in paginate(insp, "list_filters", "filters") if f["name"] == name]


def _own_tags(tags_map):
    """The template's own ``sim2real-`` tags (stack-tag propagation is not part of the claim)."""
    return {k: v for k, v in (tags_map or {}).items() if k.startswith("sim2real-")}


def _template(filter_name, scan_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Filter": _filter_resource(filter_name, "SUPPRESS"),
            "ScanConfig": {
                "Type": "AWS::InspectorV2::CodeSecurityScanConfiguration",
                "Properties": {
                    "Name": scan_name,
                    "Level": "ACCOUNT",
                    "Configuration": {
                        "ruleSetCategories": ["SCA"],
                        "periodicScanConfiguration": {"frequency": "WEEKLY"},
                    },
                    "ScopeSettings": {"projectSelectionScope": "ALL"},
                    "Tags": {"sim2real-insp": scan_name},
                },
            },
        },
        "Outputs": {
            "FilterArn": {"Value": {"Ref": "Filter"}},
            "ScanConfigArn": {"Value": {"Ref": "ScanConfig"}},
        },
    })


def _scan_configs(insp, name):
    """Every code-security scan configuration listed under exactly ``name`` (all pages)."""
    items, token = [], None
    while True:
        page = insp.list_code_security_scan_configurations(**({"nextToken": token} if token else {}))
        items += [c for c in page["configurations"] if c["name"] == name]
        token = page.get("nextToken")
        if not token:
            return items


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Inspector2 Filter and CodeSecurityScanConfiguration read back, then go.

    Refs match the entries Inspector2 lists under the declared names; criteria, action,
    description, scan settings and tags read back, and deleting the stack removes both.
    """
    cfn = ctx.client("cloudformation")
    insp = ctx.client("inspector2")
    stack = ctx.unique_name("sim2real-inspv2-")
    filter_name = ctx.unique_name("sim2real-inspf-")
    scan_name = ctx.unique_name("sim2real-inspsc-")

    stack_id = create_stack(ctx, cfn, stack, _template(filter_name, scan_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Refs against independent reads: the list entries under the declared names.
    found = _filters(insp, filter_name)
    got = [(f["arn"], f["ownerId"], f["action"], f.get("description"), f["criteria"],
            _own_tags(f.get("tags"))) for f in found]
    assert got == [(out["FilterArn"], ctx.account, "SUPPRESS", "sim2real filter",
                    {"title": [{"comparison": "EQUALS", "value": filter_name}]},
                    {"sim2real-insp": filter_name})], f"ListFilters entries {got!r}"
    scans = [c["scanConfigurationArn"] for c in _scan_configs(insp, scan_name)]
    assert scans == [out["ScanConfigArn"]], f"listed scan configurations {scans!r}, {out!r}"
    detail = insp.get_code_security_scan_configuration(scanConfigurationArn=scans[0])
    got = (detail["name"], detail["level"], detail["configuration"]["ruleSetCategories"],
           detail["configuration"]["periodicScanConfiguration"]["frequency"],
           detail["scopeSettings"], _own_tags(detail.get("tags")))
    assert got == (scan_name, "ACCOUNT", ["SCA"], "WEEKLY", {"projectSelectionScope": "ALL"},
                   {"sim2real-insp": scan_name}), f"scan configuration {got!r}"

    delete_stack(cfn, stack_id)
    gone = insp.list_filters(arns=[out["FilterArn"]])["filters"]
    assert gone == [], f"ListFilters(arns=[{out['FilterArn']!r}]) still returns {gone!r}"
    scan_gone = ("ResourceNotFoundException", "Scan configuration not found")
    expect_error(lambda: insp.get_code_security_scan_configuration(
        scanConfigurationArn=out["ScanConfigArn"]), *scan_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
