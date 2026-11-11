"""deploy-ssm-patchbaseline-via-cloudformation-then-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ssm-patchbaseline-via-cloudformation-then-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

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

_RULES = {"PatchRules": [{
    "PatchFilterGroup": {"PatchFilters": [{"Key": "CLASSIFICATION", "Values": ["Security"]}]},
    "ApproveAfterDays": 7,
    "ComplianceLevel": "CRITICAL",
}]}


def _template(name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "PB": {
                "Type": "AWS::SSM::PatchBaseline",
                "Properties": {"Name": name, "OperatingSystem": "AMAZON_LINUX_2023",
                               "ApprovalRules": _RULES},
            }
        },
        "Outputs": {"BaselineId": {"Value": {"Ref": "PB"}}},
    })


def _listed(ssm, name):
    rows = paginate(ssm, "describe_patch_baselines", "BaselineIdentities",
                    Filters=[{"Key": "NAME_PREFIX", "Values": [name]}])
    return [b["BaselineId"] for b in rows if b["BaselineName"] == name]


def _own_tags(ssm, resource_type, resource_id):
    rows = ssm.list_tags_for_resource(ResourceType=resource_type, ResourceId=resource_id)
    return {t["Key"]: t["Value"] for t in rows["TagList"] if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation SSM patch baseline reads back its OperatingSystem and ApprovalRules.

    Ref is the baseline DescribePatchBaselines lists under the templated name, the stack tag reads
    back, and the stack delete removes it from both reads.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-ssmpb-stack-")
    baseline_name = ctx.unique_name("sim2real-ssmpb-")

    stack_id = create_stack(ctx, cfn, stack, _template(baseline_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    baseline_id = stack_outputs(cfn, stack_id)["BaselineId"]

    # Ref against an independent read: the name-prefix listing, not a describe by the Ref.
    assert _listed(ssm, baseline_name) == [baseline_id], (
        f"DescribePatchBaselines for {baseline_name!r} found {_listed(ssm, baseline_name)!r}"
    )
    read = ssm.get_patch_baseline(BaselineId=baseline_id)
    got = {k: read[k] for k in ("BaselineId", "Name", "OperatingSystem")}
    want = {"BaselineId": baseline_id, "Name": baseline_name,
            "OperatingSystem": "AMAZON_LINUX_2023"}
    assert got == want, f"GetPatchBaseline reads {got!r}, expected {want!r}"
    # Per rule, only the fields the template sets: the service fills in defaults for the rest.
    read_rules = read["ApprovalRules"]["PatchRules"]
    got_rules = [{k: rule.get(k) for k in want_rule}
                 for rule, want_rule in zip(read_rules, _RULES["PatchRules"])]
    assert len(read_rules) == len(_RULES["PatchRules"]) and got_rules == _RULES["PatchRules"], (
        f"GetPatchBaseline ApprovalRules reads {read['ApprovalRules']!r}, expected {_RULES!r}"
    )
    baseline_tags = _own_tags(ssm, "PatchBaseline", baseline_id)
    assert baseline_tags == {"sim2real": stack}, f"patch baseline tags {baseline_tags!r}"

    delete_stack(cfn, stack_id)
    gone = ("DoesNotExistException", "Patch Baseline to be retrieved does not exist.")
    expect_error(lambda: ssm.get_patch_baseline(BaselineId=baseline_id), *gone)
    left = _listed(ssm, baseline_name)
    assert left == [], f"DescribePatchBaselines still lists {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
