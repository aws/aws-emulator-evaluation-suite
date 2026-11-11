"""deploy-apigatewayv2-cfn-websocket-response-and-model-removal."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-websocket-response-and-model-removal"
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

_SCHEMA_OBJ = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "title": "SimParityModel",
    "type": "object",
    "properties": {"action": {"type": "string"}},
}


def _template(api_name, model_name, with_children=True):
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "WsApi": {
                "Type": "AWS::ApiGatewayV2::Api",
                "Properties": {
                    "Name": api_name,
                    "ProtocolType": "WEBSOCKET",
                    "RouteSelectionExpression": "$request.body.action",
                },
            },
            "Integration": {
                "Type": "AWS::ApiGatewayV2::Integration",
                "Properties": {"ApiId": {"Ref": "WsApi"}, "IntegrationType": "MOCK"},
            },
            "IntegrationResponse": {
                "Type": "AWS::ApiGatewayV2::IntegrationResponse",
                "Properties": {
                    "ApiId": {"Ref": "WsApi"},
                    "IntegrationId": {"Ref": "Integration"},
                    "IntegrationResponseKey": "$default",
                    "ResponseTemplates": {"application/json": "{}"},
                },
            },
            "Route": {
                "Type": "AWS::ApiGatewayV2::Route",
                "Properties": {
                    "ApiId": {"Ref": "WsApi"},
                    "RouteKey": "ping",
                    "Target": {"Fn::Sub": "integrations/${Integration}"},
                    "RouteResponseSelectionExpression": "$default",
                },
            },
            "RouteResponse": {
                "Type": "AWS::ApiGatewayV2::RouteResponse",
                "Properties": {
                    "ApiId": {"Ref": "WsApi"},
                    "RouteId": {"Ref": "Route"},
                    "RouteResponseKey": "$default",
                },
            },
            "Model": {
                "Type": "AWS::ApiGatewayV2::Model",
                "Properties": {
                    "ApiId": {"Ref": "WsApi"},
                    "Name": model_name,
                    "Schema": _SCHEMA_OBJ,
                    "ContentType": "application/json",
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Ref": "WsApi"}},
            "IntegrationId": {"Value": {"Ref": "Integration"}},
            "RouteId": {"Value": {"Ref": "Route"}},
            "RouteResponseId": {"Value": {"Ref": "RouteResponse"}},
            "IntegrationResponseId": {"Value": {"Ref": "IntegrationResponse"}},
            "ModelId": {"Value": {"Ref": "Model"}},
        },
    }
    if not with_children:
        for logical in ("IntegrationResponse", "RouteResponse", "Model"):
            del body["Resources"][logical]
            del body["Outputs"][logical + "Id"]
    return json.dumps(body)


def _own_api(agw, name):
    return [a for a in paginate(agw, "get_apis", "Items") if a["Name"] == name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation WEBSOCKET RouteResponse, IntegrationResponse and Model read back as templated.

    Each Ref matches an independent listing; an update dropping the three removes each from the
    same Api, and deleting the stack removes the Api.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    api_name = ctx.unique_name("sim2real-xsvc-wsresp-api-")
    model_name = ctx.unique_name("sim2realxsvcwsrespmodel")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-xsvc-wsresp-stk-"),
                            _template(api_name, model_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outs = stack_outputs(cfn, stack_id)

    # Every Ref against an independent listing: the Api by name, the rest within their parent.
    apis = _own_api(agw, api_name)
    got = [(a["ApiId"], a["ProtocolType"], a["RouteSelectionExpression"]) for a in apis]
    assert got == [(outs["ApiId"], "WEBSOCKET", "$request.body.action")], f"GetApis: {got!r}"
    api_id = apis[0]["ApiId"]
    integrations = paginate(agw, "get_integrations", "Items", ApiId=api_id)
    got = [(i["IntegrationId"], i["IntegrationType"]) for i in integrations]
    assert got == [(outs["IntegrationId"], "MOCK")], f"GetIntegrations: {got!r}"
    integration_id = integrations[0]["IntegrationId"]
    routes = paginate(agw, "get_routes", "Items", ApiId=api_id)
    got = [(r["RouteId"], r["RouteKey"], r.get("Target"), r.get("RouteResponseSelectionExpression"))
           for r in routes]
    want = [(outs["RouteId"], "ping", f"integrations/{integration_id}", "$default")]
    assert got == want, f"GetRoutes: {got!r}, expected {want!r}"
    route_id = routes[0]["RouteId"]

    responses = paginate(agw, "get_route_responses", "Items", ApiId=api_id, RouteId=route_id)
    got = [(r["RouteResponseId"], r["RouteResponseKey"]) for r in responses]
    assert got == [(outs["RouteResponseId"], "$default")], f"GetRouteResponses: {got!r}"
    responses = paginate(agw, "get_integration_responses", "Items", ApiId=api_id,
                         IntegrationId=integration_id)
    got = [(r["IntegrationResponseId"], r["IntegrationResponseKey"], r.get("ResponseTemplates"))
           for r in responses]
    want = [(outs["IntegrationResponseId"], "$default", {"application/json": "{}"})]
    assert got == want, f"GetIntegrationResponses: {got!r}, expected {want!r}"
    models = paginate(agw, "get_models", "Items", ApiId=api_id)
    got = [(m["ModelId"], m["Name"], m["ContentType"], json.loads(m["Schema"])) for m in models]
    want = [(outs["ModelId"], model_name, "application/json", _SCHEMA_OBJ)]
    assert got == want, f"GetModels: {got!r}, expected {want!r}"
    model_id = models[0]["ModelId"]
    created = agw.get_api(ApiId=api_id)["CreatedDate"]

    # Children before the parent: an update dropping the three leaves the SAME Api, Integration
    # and Route with no responses and no model.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(api_name, model_name, with_children=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    left = (paginate(agw, "get_route_responses", "Items", ApiId=api_id, RouteId=route_id),
            paginate(agw, "get_integration_responses", "Items", ApiId=api_id,
                     IntegrationId=integration_id),
            paginate(agw, "get_models", "Items", ApiId=api_id))
    assert left == ([], [], []), f"after the update the Api still lists {left!r}"
    model_gone = ("NotFoundException", f"Invalid model identifier specified: {model_id}")
    expect_error(lambda: agw.get_model(ApiId=api_id, ModelId=model_id), *model_gone)
    after = agw.get_api(ApiId=api_id)["CreatedDate"]
    assert after == created, f"the Api CreatedDate changed across the update: {after!r}"

    delete_stack(cfn, stack_id)
    left = _own_api(agw, api_name)
    assert left == [], f"GetApis still lists the deleted stack's Api: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
