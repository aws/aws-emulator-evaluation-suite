"""sam-websocketapi-missing-route-selection-expression-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-websocketapi-missing-route-selection-expression-rejected"
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
__ROUTE_SELECTION__      Auth:
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

_WITH_ROUTE_SELECTION = "      RouteSelectionExpression: $request.body.action\n"
_TRANSFORM_REASON = (
    "Transform AWS::Serverless-2016-10-31 failed with: Invalid Serverless Application "
    "Specification document. Number of errors found: 1. Resource with id [WsApi] is "
    "invalid. Missing required property 'RouteSelectionExpression'."
)


@tags("axis:rejection", "cap:c2", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A WebSocketApi with no RouteSelectionExpression fails the SAM transform and creates nothing;
    the same template with the expression deploys the API, its routes and the function."""
    cf = ctx.client("cloudformation")
    apigatewayv2 = ctx.client("apigatewayv2")
    awslambda = ctx.client("lambda")

    bad_function_name = ctx.unique_name("sim2real-sam-wsneg-bad-fn-")
    ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{bad_function_name}"))
    bad_stack_id, change_set, status = create_stack_via_change_set(
        ctx, cf, ctx.unique_name("sim2real-sam-wsneg-bad-"),
        _TEMPLATE.replace("__ROUTE_SELECTION__", "")
        .replace("__FUNCTION_NAME__", bad_function_name), _CAPS)
    assert status is None, f"the refused change set must not be executed; stack ended {status!r}"
    got = (change_set["Status"], change_set.get("StatusReason"))
    assert got == ("FAILED", _TRANSFORM_REASON), (
        f"the transform must refuse the missing property: expected {('FAILED', _TRANSFORM_REASON)!r}, "
        f"got {got!r}"
    )
    resources = cf.describe_stack_resources(StackName=bad_stack_id)["StackResources"]
    assert resources == [], f"a refused transform must create no resources; got {resources!r}"
    partition = bad_stack_id.split(":")[1]
    function_absent = ("ResourceNotFoundException",
                       f"Function not found: arn:{partition}:lambda:{ctx.region}:{ctx.account}:"
                       f"function:{bad_function_name}")
    expect_error(lambda: awslambda.get_function(FunctionName=bad_function_name),
                 *function_absent)

    good_function_name = ctx.unique_name("sim2real-sam-wsneg-good-fn-")
    ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{good_function_name}"))
    good_stack_id, good_change_set, good_status = create_stack_via_change_set(
        ctx, cf, ctx.unique_name("sim2real-sam-wsneg-good-"),
        _TEMPLATE.replace("__ROUTE_SELECTION__", _WITH_ROUTE_SELECTION)
        .replace("__FUNCTION_NAME__", good_function_name), _CAPS)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack ended {good_status!r} (change set {good_change_set['Status']!r}: "
        f"{good_change_set.get('StatusReason')!r}): "
        f"{decisive_rows(stack_events(cf, good_stack_id))!r}"
    )
    good_outputs = stack_outputs(cf, good_stack_id)
    # Ref against an independent read: the SAM-expanded API's PhysicalResourceId, listed by GetApis.
    physical = cf.describe_stack_resource(
        StackName=good_stack_id, LogicalResourceId="WsApi"
    )["StackResourceDetail"]["PhysicalResourceId"]
    listed = [a["ApiId"] for a in paginate(apigatewayv2, "get_apis", "Items")
              if a["ApiId"] == physical]
    assert listed == [good_outputs["ApiRef"]], (
        f"GetApis lists {listed!r} for WsApi {physical!r}, Ref is {good_outputs['ApiRef']!r}"
    )
    described = apigatewayv2.get_api(ApiId=good_outputs["ApiRef"])
    got_api = (described["ProtocolType"], described["RouteSelectionExpression"])
    assert got_api == ("WEBSOCKET", "$request.body.action"), (
        f"the control's API must be WEBSOCKET with the declared expression; got {described!r}"
    )
    routes = {r["RouteKey"]: r
              for r in paginate(apigatewayv2, "get_routes", "Items", ApiId=good_outputs["ApiRef"])}
    assert set(routes) == {"$connect", "$default"}, (
        f"the control must expose exactly $connect and $default; got {sorted(routes)!r}"
    )
    assert routes["$connect"]["AuthorizationType"] == "AWS_IAM", (
        f"expected $connect AuthorizationType 'AWS_IAM'; got {routes['$connect']!r}"
    )
    configured = awslambda.get_function_configuration(FunctionName=good_function_name)
    assert configured["FunctionName"] == good_function_name, (
        f"expected the control's function {good_function_name!r}; got {configured['FunctionName']!r}"
    )
    got_fn = (configured["Runtime"], configured["Handler"])
    assert got_fn == ("python3.13", "index.handler"), (
        f"expected the control's function ('python3.13', 'index.handler'); got {got_fn!r}"
    )
    # Each route is wired to an integration that invokes the template's function.
    integrations = {i["IntegrationId"]: i for i in paginate(
        apigatewayv2, "get_integrations", "Items", ApiId=good_outputs["ApiRef"])}
    by_target = {f"integrations/{i}": i for i in integrations}
    targets = {key: r.get("Target") for key, r in routes.items()}
    wired = {key: by_target.get(target) for key, target in targets.items()}
    assert None not in wired.values(), (
        f"every route must target one of {sorted(by_target)!r}; got {targets!r}"
    )
    want_uri = (f"arn:{partition}:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
                f"{configured['FunctionArn']}/invocations")
    uris = {key: integrations[i]["IntegrationUri"] for key, i in wired.items()}
    assert uris == {key: want_uri for key in routes}, (
        f"every route's integration must invoke {want_uri!r}; got {uris!r}"
    )


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
