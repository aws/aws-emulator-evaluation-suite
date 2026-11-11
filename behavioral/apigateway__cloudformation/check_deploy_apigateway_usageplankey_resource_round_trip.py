"""deploy-apigateway-usageplankey-resource-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-usageplankey-resource-round-trip"
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


def is_subsequence(want, rows):
    """True when ``want`` occurs in ``rows`` in order (gaps allowed)."""
    it = iter(rows)
    return all(w in it for w in want)


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

_NOT_FOUND = ("NotFoundException", "Invalid Usage Plan ID specified")


def _template(plan_name, key_name, with_plan_key=True):
    resources = {
        "SimPlan": {
            "Type": "AWS::ApiGateway::UsagePlan",
            "Properties": {
                "UsagePlanName": plan_name,
                "Throttle": {"RateLimit": 10.0, "BurstLimit": 5},
            },
        },
        "SimKey": {
            "Type": "AWS::ApiGateway::ApiKey",
            "Properties": {"Name": key_name, "Enabled": True},
        },
    }
    if with_plan_key:
        resources["SimPlanKey"] = {
            "Type": "AWS::ApiGateway::UsagePlanKey",
            "Properties": {
                "KeyId": {"Ref": "SimKey"},
                "KeyType": "API_KEY",
                "UsagePlanId": {"Ref": "SimPlan"},
            },
        }
    outputs = {
        "PlanRef": {"Value": {"Ref": "SimPlan"}},
        "KeyRef": {"Value": {"Ref": "SimKey"}},
    }
    if with_plan_key:
        outputs["PlanKeyRef"] = {"Value": {"Ref": "SimPlanKey"}}
        outputs["PlanKeyIdAttr"] = {"Value": {"Fn::GetAtt": ["SimPlanKey", "Id"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::ApiGateway::UsagePlanKey reads back through GetUsagePlanKey and
    GetUsagePlanKeys with the Ref/GetAtt the docs specify, and a stack update that drops only the
    UsagePlanKey removes the association while the UsagePlan and ApiKey parents still answer."""
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    stack_name = ctx.unique_name("sim2real-cfn-uplankey-")
    plan_name = ctx.unique_name("sim2real-uplankey-plan-")
    key_name = ctx.unique_name("sim2real-uplankey-key-")

    stack_id = create_stack(ctx, cfn, stack_name, _template(plan_name, key_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    plan_id, key_id = out["PlanRef"], out["KeyRef"]

    # The parents' Refs against independent listings by name, with every templated property.
    plans = [u for u in paginate(apigw, "get_usage_plans", "items") if u["name"] == plan_name]
    assert [u["id"] for u in plans] == [plan_id], f"GetUsagePlans found {plans!r} for {plan_id!r}"
    throttle = plans[0].get("throttle")
    assert throttle == {"rateLimit": 10.0, "burstLimit": 5}, f"UsagePlan throttle {throttle!r}"
    keys = [k for k in paginate(apigw, "get_api_keys", "items", nameQuery=key_name)
            if k["name"] == key_name]
    assert [(k["id"], k["enabled"]) for k in keys] == [(key_id, True)], (
        f"GetApiKeys found {keys!r} for {key_id!r}"
    )

    # Ref and GetAtt Id both return the documented "<keyId>:<usagePlanId>" composite.
    want_ref = f"{key_id}:{plan_id}"
    assert out["PlanKeyRef"] == want_ref, f"Ref {out['PlanKeyRef']!r} != documented {want_ref!r}"
    assert out["PlanKeyIdAttr"] == want_ref, (
        f"GetAtt Id {out['PlanKeyIdAttr']!r} != documented {want_ref!r}"
    )
    # Compare the key id against an independent list read, never a read keyed by the Ref.
    items = paginate(apigw, "get_usage_plan_keys", "items", usagePlanId=plan_id)
    assert [i["id"] for i in items] == [key_id], (
        f"GetUsagePlanKeys for {plan_id!r} returned {items!r}, expected exactly {key_id!r}"
    )
    assert items[0]["type"] == "API_KEY", f"listed type {items[0]['type']!r} != API_KEY"
    assert items[0]["name"] == key_name, f"listed name {items[0]['name']!r} != {key_name!r}"

    # The templated KeyType property, read back by GetUsagePlanKey (keyed by plan+key, not Ref).
    key_assoc = apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    assert key_assoc["id"] == key_id, f"GetUsagePlanKey id {key_assoc['id']!r} != {key_id!r}"
    assert key_assoc["type"] == "API_KEY", f"GetUsagePlanKey type {key_assoc['type']!r} != API_KEY"
    assert key_assoc["name"] == key_name, f"GetUsagePlanKey name {key_assoc['name']!r} != {key_name!r}"

    # Child before parent: an update that drops only SimPlanKey removes the association while the
    # UsagePlan and ApiKey it links still answer.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(plan_name, key_name, with_plan_key=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"plan-key-dropping update ended {status!r}: "
        f"{decisive_rows(stack_events(cfn, stack_id), 'SimPlanKey')!r}"
    )
    rows = decisive_rows(stack_events(cfn, stack_id), "SimPlanKey")
    assert is_subsequence([("SimPlanKey", "DELETE_COMPLETE")], rows), (
        f"expected SimPlanKey DELETE_COMPLETE among {rows!r}"
    )
    expect_error(lambda: apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id), *_NOT_FOUND)
    remaining = paginate(apigw, "get_usage_plan_keys", "items", usagePlanId=plan_id)
    assert remaining == [], f"GetUsagePlanKeys for {plan_id!r} still lists {remaining!r}"
    # Parents survive: both still answer for the ids this check created.
    plan = apigw.get_usage_plan(usagePlanId=plan_id)
    assert plan["id"] == plan_id, f"parent UsagePlan {plan_id!r} no longer answers: {plan!r}"
    key = apigw.get_api_key(apiKey=key_id)
    assert key["id"] == key_id, f"parent ApiKey {key_id!r} no longer answers: {key!r}"

    delete_stack(cfn, stack_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
