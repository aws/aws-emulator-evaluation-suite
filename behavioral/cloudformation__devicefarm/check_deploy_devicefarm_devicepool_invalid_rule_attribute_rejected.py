"""deploy-devicefarm-devicepool-invalid-rule-attribute-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-devicefarm-devicepool-invalid-rule-attribute-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "devicefarm"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_VALID_RULE = {"Attribute": "PLATFORM", "Operator": "EQUALS", "Value": '"ANDROID"'}
_VALID_RULE_API = {"attribute": "PLATFORM", "operator": "EQUALS", "value": '"ANDROID"'}
_BAD_ATTRIBUTE = "NOT_A_REAL_ATTRIBUTE"
_SUPPORTED = (
    "ARN, PLATFORM, FORM_FACTOR, MANUFACTURER, REMOTE_ACCESS_ENABLED, REMOTE_DEBUG_ENABLED, "
    "APPIUM_VERSION, INSTANCE_ARN, INSTANCE_LABELS, FLEET_TYPE, OS_VERSION, MODEL, AVAILABILITY"
)


def _template(project_name, pool_name, rule):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Proj": {"Type": "AWS::DeviceFarm::Project", "Properties": {"Name": project_name}},
            "Pool": {"Type": "AWS::DeviceFarm::DevicePool", "Properties": {
                "Name": pool_name,
                "ProjectArn": {"Fn::GetAtt": ["Proj", "Arn"]},
                "Rules": [rule],
            }},
        },
        "Outputs": {
            "ProjRef": {"Value": {"Ref": "Proj"}},
            "PoolRef": {"Value": {"Ref": "Pool"}},
        },
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Device Farm device pool with an unsupported Rule attribute fails early
    validation and creates no project, while the same template with a supported attribute deploys
    and reads back through Device Farm.
    """
    cf = ctx.client("cloudformation")
    df = ctx.client("devicefarm")
    good_project = ctx.unique_name("sim2real-cfndf-badrule-good-proj-")
    good_pool = ctx.unique_name("sim2real-cfndf-badrule-good-pool-")
    bad_project = ctx.unique_name("sim2real-cfndf-badrule-bad-proj-")
    bad_pool = ctx.unique_name("sim2real-cfndf-badrule-bad-pool-")

    # Positive control: same template, the one property given a VALID value (never dropped).
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfndf-badrule-goodstack-"),
                           _template(good_project, good_pool, _VALID_RULE))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cf, good_id)
    projects = [p["arn"] for p in paginate(df, "list_projects", "projects")
                if p["name"] == good_project]
    assert projects == [out["ProjRef"]], f"ListProjects for {good_project!r}: {projects!r}"
    pools = [(p["arn"], p["rules"]) for p in paginate(
        df, "list_device_pools", "devicePools", arn=out["ProjRef"], type="PRIVATE")
        if p["name"] == good_pool]
    assert pools == [(out["PoolRef"], [_VALID_RULE_API])], f"control pools {pools!r}"

    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfndf-badrule-badstack-"),
                          _template(bad_project, bad_pool, {**_VALID_RULE,
                                                            "Attribute": _BAD_ATTRIBUTE}))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    assert rows == [(
        "Pool", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        f"{_BAD_ATTRIBUTE} is not a valid enum value. Supported values: [{_SUPPORTED}]",
        "/Resources/Pool/Properties/Rules/0/Attribute",
    )], f"validation rows {rows!r}"

    # Early validation runs before any resource is created, so neither the pool nor its parent
    # project exists -- proven through Device Farm, by the name each would have had.
    projects = paginate(df, "list_projects", "projects")
    matched = [p for p in projects if p["name"] == bad_project]
    assert matched == [], f"the rolled-back project is listed: {matched!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
