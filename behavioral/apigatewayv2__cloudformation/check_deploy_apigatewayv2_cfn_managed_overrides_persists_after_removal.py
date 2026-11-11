"""deploy-apigatewayv2-cfn-managed-overrides-persists-after-removal."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-managed-overrides-persists-after-removal"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation"]

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


# ---- Check-specific: the template, then run(). ----

_TARGET = "https://example.com"


def _template(api_name, description, with_overrides):
    resources = {
        "Api": {
            "Type": "AWS::ApiGatewayV2::Api",
            "Properties": {
                "Name": api_name,
                "ProtocolType": "HTTP",
                "Target": _TARGET,
                # The quick-create stage serves nothing: its default endpoint is disabled.
                "DisableExecuteApiEndpoint": True,
            },
        },
    }
    outputs = {"ApiId": {"Value": {"Ref": "Api"}}}
    if with_overrides:
        resources["Overrides"] = {
            "Type": "AWS::ApiGatewayV2::ApiGatewayManagedOverrides",
            "DependsOn": ["Api"],
            "Properties": {"ApiId": {"Ref": "Api"}, "Stage": {"Description": description}},
        }
        outputs["OverridesId"] = {"Value": {"Ref": "Overrides"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _own_api(agw, name):
    return [a for a in paginate(agw, "get_apis", "Items") if a["Name"] == name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ApiGatewayV2 managed override writes the quick-create stage's Description.

    Its Ref is the Api's id; removing it only stops CloudFormation tracking it, so the same
    stage keeps the override, and deleting the stack removes the Api.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    api_name = ctx.unique_name("sim2real-xsvc-qcover-api-")
    description = ctx.unique_name("sim2real-xsvc-qcover-desc-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-xsvc-qcover-stk-"),
                            _template(api_name, description, with_overrides=True))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Both Refs against an independent GetApis read by the templated name.
    apis = _own_api(agw, api_name)
    got = [(a["ApiId"], a["ProtocolType"], a.get("DisableExecuteApiEndpoint")) for a in apis]
    assert got == [(out["ApiId"], "HTTP", True)], f"GetApis found {got!r} for {out['ApiId']!r}"
    api_id = apis[0]["ApiId"]
    assert out["OverridesId"] == api_id, f"Overrides Ref {out['OverridesId']!r} != {api_id!r}"

    stage = agw.get_stage(ApiId=api_id, StageName="$default")
    got = (stage.get("Description"), stage.get("ApiGatewayManaged"), stage.get("AutoDeploy"))
    assert got == (description, True, True), f"the quick-create $default stage reads {got!r}"
    routes = [(r["RouteKey"], r.get("ApiGatewayManaged"))
              for r in paginate(agw, "get_routes", "Items", ApiId=api_id)]
    assert routes == [("$default", True)], f"the quick-create routes read {routes!r}"
    uris = [i.get("IntegrationUri") for i in paginate(agw, "get_integrations", "Items",
                                                         ApiId=api_id)]
    assert uris == [_TARGET], f"the quick-create integration URIs read {uris!r}"

    # Removing the override leaves the SAME stage (CreatedDate) with the override's Description.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(api_name, description, with_overrides=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"override-removing update ended {status!r}"
    after = agw.get_stage(ApiId=api_id, StageName="$default")
    got = (after.get("CreatedDate"), after.get("Description"))
    assert got == (stage["CreatedDate"], description), (
        f"after removing the override the $default stage reads {got!r}"
    )

    delete_stack(cfn, stack_id)
    left = _own_api(agw, api_name)
    assert left == [], f"GetApis still lists the deleted stack's Api: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
