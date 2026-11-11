"""deploy-apigatewayv2-cfn-deployment-status-and-removal."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-deployment-status-and-removal"
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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_DEPLOYMENT_NOT_FOUND = ("NotFoundException", "Invalid Deployment identifier specified")
_URI = "https://example.com"


def _template(api_name, description, with_deployment=True):
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Api": {
                "Type": "AWS::ApiGatewayV2::Api",
                "Properties": {"Name": api_name, "ProtocolType": "HTTP"},
            },
            "Integration": {
                "Type": "AWS::ApiGatewayV2::Integration",
                "Properties": {
                    "ApiId": {"Ref": "Api"},
                    "IntegrationType": "HTTP_PROXY",
                    "IntegrationMethod": "ANY",
                    "IntegrationUri": "https://example.com",
                    "PayloadFormatVersion": "1.0",
                },
            },
            "Route": {
                "Type": "AWS::ApiGatewayV2::Route",
                "Properties": {
                    "ApiId": {"Ref": "Api"},
                    "RouteKey": "GET /ping",
                    "Target": {"Fn::Sub": "integrations/${Integration}"},
                },
            },
            "Deployment": {
                "Type": "AWS::ApiGatewayV2::Deployment",
                "DependsOn": ["Route"],
                "Properties": {"ApiId": {"Ref": "Api"}, "Description": description},
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Ref": "Api"}},
            "DeploymentId": {"Value": {"Ref": "Deployment"}},
        },
    }
    if not with_deployment:
        del body["Resources"]["Deployment"], body["Outputs"]["DeploymentId"]
    return json.dumps(body)


def _own_api(agw, name):
    return [a for a in paginate(agw, "get_apis", "Items") if a["Name"] == name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ApiGatewayV2 Deployment reads back DEPLOYED with its Description.

    The Api, Integration and Route read back as templated; an update dropping the Deployment
    removes it from the same Api, and deleting the stack removes the Api.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    api_name = ctx.unique_name("sim2real-xsvc-depl-api-")
    description = ctx.unique_name("sim2real-xsvc-depl-desc-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-xsvc-depl-stk-"),
                            _template(api_name, description))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Refs against independent listings: the Api by name, the rest within that Api.
    apis = _own_api(agw, api_name)
    assert [(a["ApiId"], a["ProtocolType"]) for a in apis] == [(out["ApiId"], "HTTP")], (
        f"GetApis found {apis!r} for Ref {out['ApiId']!r}"
    )
    api_id = apis[0]["ApiId"]
    integrations = paginate(agw, "get_integrations", "Items", ApiId=api_id)
    got = [(i["IntegrationType"], i["IntegrationMethod"], i["IntegrationUri"],
            i["PayloadFormatVersion"]) for i in integrations]
    assert got == [("HTTP_PROXY", "ANY", _URI, "1.0")], f"GetIntegrations returned {got!r}"
    routes = paginate(agw, "get_routes", "Items", ApiId=api_id)
    got = [(r["RouteKey"], r.get("Target")) for r in routes]
    want = [("GET /ping", f"integrations/{integrations[0]['IntegrationId']}")]
    assert got == want, f"GetRoutes returned {got!r}, expected {want!r}"
    listed = [d["DeploymentId"] for d in paginate(agw, "get_deployments", "Items", ApiId=api_id)]
    assert listed == [out["DeploymentId"]], (
        f"GetDeployments listed {listed!r}, expected only the Ref {out['DeploymentId']!r}"
    )
    deployment_id = listed[0]
    got = agw.get_deployment(ApiId=api_id, DeploymentId=deployment_id)
    assert (got["Description"], got["DeploymentStatus"]) == (description, "DEPLOYED"), (
        f"GetDeployment reads {got.get('Description')!r} / {got.get('DeploymentStatus')!r}: "
        f"{got.get('DeploymentStatusMessage')!r}"
    )
    created = agw.get_api(ApiId=api_id)["CreatedDate"]

    # Child before parent: dropping only the Deployment removes it while the same Api answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(api_name, description, with_deployment=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"deployment-removing update ended {status!r}"
    read = lambda: agw.get_deployment(ApiId=api_id, DeploymentId=deployment_id)  # noqa: E731
    until_raises(read)
    expect_error(read, *_DEPLOYMENT_NOT_FOUND)
    after = agw.get_api(ApiId=api_id)["CreatedDate"]
    assert after == created, f"the Api CreatedDate changed across the update: {after!r}"

    delete_stack(cfn, stack_id)
    left = _own_api(agw, api_name)
    assert left == [], f"GetApis still lists the deleted stack's Api: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
