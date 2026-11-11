"""deploy-apigateway-usageplankey-invalid-keytype-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-apigateway-usageplankey-invalid-keytype-rejected"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----


def _template(plan_name, key_name, key_type):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SimPlan": {
                "Type": "AWS::ApiGateway::UsagePlan",
                "Properties": {"UsagePlanName": plan_name},
            },
            "SimKey": {
                "Type": "AWS::ApiGateway::ApiKey",
                "Properties": {"Name": key_name, "Enabled": True},
            },
            "SimPlanKey": {
                "Type": "AWS::ApiGateway::UsagePlanKey",
                "Properties": {
                    "KeyId": {"Ref": "SimKey"},
                    "KeyType": key_type,
                    "UsagePlanId": {"Ref": "SimPlan"},
                },
            },
        },
        "Outputs": {
            "PlanRef": {"Value": {"Ref": "SimPlan"}},
            "KeyRef": {"Value": {"Ref": "SimKey"}},
        },
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::ApiGateway::UsagePlanKey with an unsupported KeyType is refused while
    the same template with KeyType API_KEY deploys and associates the key with the plan."""
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    good_plan_name = ctx.unique_name("sim2real-uplankey-kt-good-plan-")
    good_key_name = ctx.unique_name("sim2real-uplankey-kt-good-key-")
    bad_plan_name = ctx.unique_name("sim2real-uplankey-kt-bad-plan-")
    bad_key_name = ctx.unique_name("sim2real-uplankey-kt-bad-key-")

    # Positive control: same template, KeyType given the one valid value (never dropped).
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-uplankey-kt-good-"),
                           _template(good_plan_name, good_key_name, "API_KEY"))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_out = stack_outputs(cfn, good_id)
    assoc = apigw.get_usage_plan_key(usagePlanId=good_out["PlanRef"], keyId=good_out["KeyRef"])
    got = (assoc["id"], assoc["type"], assoc["name"])
    assert got == (good_out["KeyRef"], "API_KEY", good_key_name), f"control association {got!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-uplankey-kt-bad-"),
                          _template(bad_plan_name, bad_key_name, "UNSUPPORTED_TYPE"))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"

    rows = validation_rows(cfn, bad_id)
    assert rows == [
        ("SimPlanKey", "PROPERTY_VALIDATION", "FAILED", "FAIL",
         "UNSUPPORTED_TYPE is not a valid enum value. Supported values: [API_KEY]",
         "/Resources/SimPlanKey/Properties/KeyType"),
    ], f"unexpected validation rows: {rows!r}"

    # Rollback absence through apigateway, by a name the key would have, BEFORE this check's own
    # delete: ListApiKeys filtered to this run's name never shows the rolled-back key.
    listed = [k for k in paginate(apigw, "get_api_keys", "items", nameQuery=bad_key_name)
              if k["name"] == bad_key_name]
    assert listed == [], f"the rolled-back api key is listed: {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
