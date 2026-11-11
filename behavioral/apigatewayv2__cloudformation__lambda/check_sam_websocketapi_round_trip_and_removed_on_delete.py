"""sam-websocketapi-round-trip-and-removed-on-delete."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-websocketapi-round-trip-and-removed-on-delete"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation", "lambda"]

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


def create_stack_via_change_set(ctx, cf, name, template, capabilities, timeout_s=300.0):
    """Deploy a Transform (SAM) template as `sam deploy` does: CREATE change set, execute, wait.

    Returns ``(stack_id, change_set, stack_status)``; a FAILED change set is not executed
    (status None), so the check grades ``change_set["StatusReason"]``. Cleanup is registered first.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    resp = cf.create_change_set(
        StackName=name, ChangeSetName="sim2real-create", ChangeSetType="CREATE",
        TemplateBody=template, Capabilities=list(capabilities),
        Tags=[{"Key": "sim2real", "Value": name}],
    )
    stack_id, change_set_id = resp["StackId"], resp["Id"]
    created["StackId"] = stack_id
    deadline = time.monotonic() + timeout_s
    while True:
        change_set = cf.describe_change_set(ChangeSetName=change_set_id)
        if change_set["Status"] in ("CREATE_COMPLETE", "FAILED"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"change set {change_set_id} still {change_set['Status']!r}")
        time.sleep(2)
    if change_set["Status"] == "FAILED":
        return stack_id, change_set, None
    cf.execute_change_set(ChangeSetName=change_set_id)
    return stack_id, change_set, wait_stack(cf, stack_id, timeout_s=timeout_s)


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

_CAPS = ["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"]
_ROUTE_SELECTION = "$request.body.action"

# $connect requires SigV4 (AWS_IAM), so no unsigned client can open a connection.
_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: __FUNCTION_NAME__
      Handler: index.handler
      Runtime: python3.13
      InlineCode: |
        def handler(event, context):
            return {"statusCode": 200}
  WsApi:
    Type: AWS::Serverless::WebSocketApi
    Properties:
      Name: __API_NAME__
      RouteSelectionExpression: $request.body.action
      Auth:
        AuthType: AWS_IAM
      Routes:
        $connect:
          FunctionArn: !GetAtt Fn.Arn
        $default:
          FunctionArn: !GetAtt Fn.Arn
Outputs:
  ApiRef:
    Value: !Ref WsApi
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A Serverless::WebSocketApi expands into an IAM-gated WebSocket API, its routes, Lambda
    proxy integrations and function; Ref is the listed apiId; stack delete removes API and function.
    """
    cf = ctx.client("cloudformation")
    apigatewayv2 = ctx.client("apigatewayv2")
    awslambda = ctx.client("lambda")
    stack = ctx.unique_name("sim2real-sam-wsapi-")
    function_name = ctx.unique_name("sim2real-sam-wsapi-fn-")
    api_name = ctx.unique_name("sim2real-sam-wsapi-api-")

    ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{function_name}"))

    template = (_TEMPLATE.replace("__FUNCTION_NAME__", function_name)
                .replace("__API_NAME__", api_name))
    stack_id, change_set, status = create_stack_via_change_set(ctx, cf, stack, template, _CAPS)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack} ended {status!r} (change set {change_set['Status']!r}: "
        f"{change_set.get('StatusReason')!r}): {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)
    api_id = outputs["ApiRef"]
    partition = stack_id.split(":")[1]

    listed = [a for a in paginate(apigatewayv2, "get_apis", "Items") if a["Name"] == api_name]
    assert [a["ApiId"] for a in listed] == [api_id], (
        f"Ref {api_id!r} must be the apiId GetApis lists for {api_name!r}; listed {listed!r}"
    )
    described = apigatewayv2.get_api(ApiId=api_id)
    assert described["ProtocolType"] == "WEBSOCKET", f"expected a WebSocket API; got {described!r}"
    assert described["RouteSelectionExpression"] == _ROUTE_SELECTION, (
        f"expected RouteSelectionExpression {_ROUTE_SELECTION!r}; got {described!r}"
    )

    physical_fn = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Fn")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert physical_fn == function_name, (
        f"logical id Fn must be the function {function_name!r}; got {physical_fn!r}"
    )
    configured = awslambda.get_function_configuration(FunctionName=physical_fn)
    got_fn = (configured["FunctionName"], configured["Runtime"], configured["Handler"])
    assert got_fn == (function_name, "python3.13", "index.handler"), (
        f"expected {(function_name, 'python3.13', 'index.handler')!r}; got {got_fn!r}"
    )
    function_arn = configured["FunctionArn"]
    want_uri = (f"arn:{partition}:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
                f"{function_arn}/invocations")

    routes = {r["RouteKey"]: r for r in paginate(apigatewayv2, "get_routes", "Items", ApiId=api_id)}
    assert set(routes) == {"$connect", "$default"}, (
        f"expected exactly the declared $connect and $default routes; got {sorted(routes)!r}"
    )
    assert routes["$connect"]["AuthorizationType"] == "AWS_IAM", (
        f"expected $connect AuthorizationType 'AWS_IAM'; got {routes['$connect']!r}"
    )
    integrations = {i["IntegrationId"]: i
                    for i in paginate(apigatewayv2, "get_integrations", "Items", ApiId=api_id)}
    for key, route in routes.items():
        target = re.fullmatch(r"integrations/(\w+)", route.get("Target", ""))
        assert target and target[1] in integrations, (
            f"route {key!r} must target one of the API's integrations {sorted(integrations)!r}; "
            f"got {route.get('Target')!r}"
        )
        integration = integrations[target[1]]
        got = (integration["IntegrationType"], integration["IntegrationUri"])
        assert got == ("AWS_PROXY", want_uri), (
            f"route {key!r} integration: expected {('AWS_PROXY', want_uri)!r}; got {got!r}"
        )

    policy = json.loads(awslambda.get_policy(FunctionName=function_name)["Policy"])
    grants = {(s["Effect"], json.dumps(s["Principal"], sort_keys=True), s["Action"], s["Resource"])
              for s in policy["Statement"]}
    want_grant = ("Allow", json.dumps({"Service": "apigateway.amazonaws.com"}),
                  "lambda:InvokeFunction", function_arn)
    assert grants == {want_grant}, (
        f"every function permission must let API Gateway invoke it; expected {{{want_grant!r}}}, "
        f"got {grants!r}"
    )

    api_gone = ("NotFoundException", f"Invalid API identifier specified {ctx.account}:{api_id}")
    function_gone = ("ResourceNotFoundException",
                     f"Function not found: arn:{partition}:lambda:{ctx.region}:{ctx.account}:"
                     f"function:{function_name}")
    delete_stack(cf, stack_id)
    expect_error(lambda: apigatewayv2.get_api(ApiId=api_id), *api_gone)
    expect_error(lambda: awslambda.get_function(FunctionName=function_name), *function_gone)


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
