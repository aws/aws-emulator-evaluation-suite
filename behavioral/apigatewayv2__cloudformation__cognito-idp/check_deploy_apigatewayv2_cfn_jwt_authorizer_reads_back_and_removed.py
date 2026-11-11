"""deploy-apigatewayv2-cfn-jwt-authorizer-reads-back-and-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-jwt-authorizer-reads-back-and-removed"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation", "cognito-idp"]

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

_AUTHORIZER_NOT_FOUND = ("NotFoundException", "Invalid Authorizer identifier specified")


def _template(api_name, authorizer_name, pool_name, client_name, with_authorizer=True):
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": pool_name},
            },
            "PoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {"UserPoolId": {"Ref": "Pool"}, "ClientName": client_name},
            },
            "Api": {
                "Type": "AWS::ApiGatewayV2::Api",
                "Properties": {"Name": api_name, "ProtocolType": "HTTP"},
            },
            "Authorizer": {
                "Type": "AWS::ApiGatewayV2::Authorizer",
                "Properties": {
                    "ApiId": {"Ref": "Api"},
                    "Name": authorizer_name,
                    "AuthorizerType": "JWT",
                    "IdentitySource": ["$request.header.Authorization"],
                    "JwtConfiguration": {
                        "Issuer": {
                            "Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${Pool}"
                        },
                        "Audience": [{"Ref": "PoolClient"}],
                    },
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Ref": "Api"}},
            "AuthorizerId": {"Value": {"Ref": "Authorizer"}},
            "PoolId": {"Value": {"Ref": "Pool"}},
            "PoolClientId": {"Value": {"Ref": "PoolClient"}},
        },
    }
    if not with_authorizer:
        del body["Resources"]["Authorizer"], body["Outputs"]["AuthorizerId"]
    return json.dumps(body)


def _own_api(agw, name):
    return [a for a in paginate(agw, "get_apis", "Items") if a["Name"] == name]


def _own_pool(idp, name):
    return [p for p in paginate(idp, "list_user_pools", "UserPools", MaxResults=60)
            if p["Name"] == name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation JWT ApiGatewayV2 Authorizer on a real Cognito issuer reads back as templated.

    Every Ref matches an independent listing; an update dropping the Authorizer removes it from
    the same Api, and deleting the stack removes the Api and the user pool.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    idp = ctx.client("cognito-idp")
    api_name = ctx.unique_name("sim2real-xsvc-jwtauth-api-")
    authorizer_name = ctx.unique_name("sim2real-xsvc-jwtauth-authz-")
    pool_name = ctx.unique_name("sim2real-xsvc-jwtauth-pool-")
    client_name = ctx.unique_name("sim2real-xsvc-jwtauth-client-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-xsvc-jwtauth-stk-"),
                            _template(api_name, authorizer_name, pool_name, client_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Cognito Refs against Cognito's own listings by the templated names.
    pools = _own_pool(idp, pool_name)
    assert [p["Id"] for p in pools] == [out["PoolId"]], f"ListUserPools found {pools!r}"
    pool_id = pools[0]["Id"]
    clients = [c["ClientId"] for c in paginate(idp, "list_user_pool_clients", "UserPoolClients",
                                               UserPoolId=pool_id)
               if c["ClientName"] == client_name]
    assert clients == [out["PoolClientId"]], f"ListUserPoolClients found {clients!r}"

    apis = _own_api(agw, api_name)
    assert [(a["ApiId"], a["ProtocolType"]) for a in apis] == [(out["ApiId"], "HTTP")], (
        f"GetApis found {apis!r} for Ref {out['ApiId']!r}"
    )
    api_id = apis[0]["ApiId"]
    authorizers = paginate(agw, "get_authorizers", "Items", ApiId=api_id)
    got = [(a["AuthorizerId"], a["Name"], a["AuthorizerType"], a["IdentitySource"],
            a["JwtConfiguration"]) for a in authorizers]
    issuer = f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    want = [(out["AuthorizerId"], authorizer_name, "JWT", ["$request.header.Authorization"],
             {"Issuer": issuer, "Audience": clients})]
    assert got == want, f"GetAuthorizers returned {got!r}, expected {want!r}"
    authorizer_id = authorizers[0]["AuthorizerId"]
    created = agw.get_api(ApiId=api_id)["CreatedDate"]

    # Child before parent: dropping only the Authorizer removes it while the same Api answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(
        api_name, authorizer_name, pool_name, client_name, with_authorizer=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"authorizer-removing update ended {status!r}"
    read = lambda: agw.get_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)  # noqa: E731
    until_raises(read)
    expect_error(read, *_AUTHORIZER_NOT_FOUND)
    after = agw.get_api(ApiId=api_id)["CreatedDate"]
    assert after == created, f"the Api CreatedDate changed across the update: {after!r}"

    delete_stack(cfn, stack_id)
    left = (_own_api(agw, api_name), _own_pool(idp, pool_name))
    assert left == ([], []), f"the deleted stack's Api / user pool are still listed: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
