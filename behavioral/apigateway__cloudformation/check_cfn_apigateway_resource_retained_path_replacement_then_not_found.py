"""cfn-apigateway-resource-retained-path-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigateway-resource-retained-path-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: API Gateway's refusal of a REST API that no longer exists, naming account and API id.
_NOT_FOUND_CODE = "NotFoundException"
_NOT_FOUND_MESSAGE = "Invalid API identifier specified {account}:{api_id}"
#: API Gateway's refusal of a resource or method that no longer exists in an existing API.
_RESOURCE_GONE = (_NOT_FOUND_CODE, "Invalid Resource identifier specified")
_METHOD_GONE = (_NOT_FOUND_CODE, "Invalid Method identifier specified")


def _template(api_name: str, path_part: str | None) -> str:
    """A REST API; with *path_part*, a child resource and a MOCK GET on it."""
    resources: dict = {
        "Api": {
            "Type": "AWS::ApiGateway::RestApi",
            "Properties": {
                "Name": api_name,
                "EndpointConfiguration": {"Types": ["REGIONAL"]},
                # The API answers only TestInvokeMethod: no default execute-api endpoint.
                "DisableExecuteApiEndpoint": True,
                "Tags": _TAGS,
            },
        },
    }
    if path_part is not None:
        resources["Res"] = {
            "Type": "AWS::ApiGateway::Resource",
            # PathPart is create-only, so changing it replaces the resource.
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                "PathPart": path_part,
            },
        }
        resources["ResMethod"] = {
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "ResourceId": {"Ref": "Res"},
                "HttpMethod": "GET",
                "AuthorizationType": "AWS_IAM",
                "Integration": {
                    "Type": "MOCK",
                    "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                    "IntegrationResponses": [
                        {
                            "StatusCode": "200",
                            "ResponseTemplates": {
                                "application/json": json.dumps({"path": path_part})
                            },
                        }
                    ],
                },
                "MethodResponses": [{"StatusCode": "200"}],
            },
        }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": resources,
            "Outputs": {"RootResourceId": {"Value": {"Fn::GetAtt": ["Api", "RootResourceId"]}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation API Gateway resource has the template's path and serves its MOCK method.

    Every Resource property is create-only, so there is no in-place step: a PathPart change under
    UpdateReplacePolicy Retain keeps the old resource; removal and delete answer NotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-resource.html
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-cfnres-")
    stack_name = ctx.unique_name("sim2real-cfnres-stack-")
    ref = {"stack": stack_name}

    # The retained resource lives inside the stack's API, which the stack delete removes.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, API Gateway's view, and the method answering
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(api_name, "first"), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    api_id, old_res = ids["Api"], ids["Res"]
    root_id = _outputs(stack)["RootResourceId"]
    _assert_resource(apigw, api_id, old_res, root_id, "first")
    _assert_test_invoke(apigw, api_id, old_res, "first")

    # ---- 2. replacement under UpdateReplacePolicy Retain: a new resource, the old one kept
    events = _update(ctx, cfn, ref, _template(api_name, "second"))
    ids = _physical_ids(cfn, ref["stack"])
    new_res = ids["Res"]
    assert ids["Api"] == api_id and new_res != old_res, f"only the resource is replaced: {ids!r}"
    _assert_replaced_and_retained(_rows(events, set(), "Res"), old_res, new_res, "Res")
    _assert_resource(apigw, api_id, new_res, root_id, "second")
    _assert_test_invoke(apigw, api_id, new_res, "second")
    _assert_resource(apigw, api_id, old_res, root_id, "first")
    # The method on the old resource was replaced without Retain, so CloudFormation deleted it.
    got = _error(lambda: apigw.get_method(restApiId=api_id, resourceId=old_res, httpMethod="GET"))
    assert got == _METHOD_GONE, (
        f"GET on the retained resource answered {got!r}, not {_METHOD_GONE!r}"
    )

    # ---- 3. removal from the template: CloudFormation deletes the resource it tracks
    events = _update(ctx, cfn, ref, _template(api_name, None))
    deleted = [s for s, _, pid in _rows(events, set(), "Res") if pid == new_res]
    assert deleted == ["DELETE_IN_PROGRESS", "DELETE_COMPLETE"], f"Res removal events: {deleted!r}"
    got = _wait_error(
        ctx,
        lambda: apigw.get_resource(restApiId=api_id, resourceId=new_res),
        _NOT_FOUND_CODE,
        f"resource {new_res}",
    )
    assert got == _RESOURCE_GONE, (
        f"GetResource after removal answered {got!r}, not {_RESOURCE_GONE!r}"
    )
    _assert_resource(apigw, api_id, old_res, root_id, "first")

    # ---- 4. delete: API Gateway no longer knows the stack's API
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: apigw.get_rest_api(restApiId=api_id), _NOT_FOUND_CODE, f"REST API {api_id}"
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(account=ctx.account, api_id=api_id))
    assert got == want, f"GetRestApi after the stack delete answered {got!r}, expected {want!r}"


def _assert_resource(apigw, api_id: str, res_id: str, root_id: str, path_part: str) -> None:
    """GetResource reports the template's parent, path part and full path exactly."""
    res = apigw.get_resource(restApiId=api_id, resourceId=res_id)
    got = {k: res.get(k) for k in ("id", "parentId", "pathPart", "path")}
    want = {"id": res_id, "parentId": root_id, "pathPart": path_part, "path": f"/{path_part}"}
    assert got == want, f"GetResource {res_id}: {got!r}, expected {want!r}"


def _assert_test_invoke(apigw, api_id: str, res_id: str, path_part: str) -> None:
    """TestInvokeMethod runs the resource's MOCK integration and returns its response template."""
    resp = apigw.test_invoke_method(restApiId=api_id, resourceId=res_id, httpMethod="GET")
    got = (resp.get("status"), json.loads(resp.get("body") or "null"))
    assert got == (200, {"path": path_part}), (
        f"TestInvokeMethod GET /{path_part} answered {got!r}, expected (200, path {path_part!r})"
    )


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ctx=None
    and waits the full cap; in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Its waits use fixed caps (ctx=None), never the run's remaining time.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"])
    _delete_stack(None, cfn, stack["StackId"])


def _update(ctx, cfn, ref: dict, body: str, **kwargs) -> list[dict]:
    """UpdateStack to *body*, require UPDATE_COMPLETE, and return the events it added."""
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=body, Tags=_TAGS, **kwargs)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    return [e for e in _events(cfn, ref["stack"]) if e["EventId"] not in seen]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
