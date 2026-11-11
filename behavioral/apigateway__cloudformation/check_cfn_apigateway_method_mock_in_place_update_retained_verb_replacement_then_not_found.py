"""cfn-apigateway-method-mock-in-place-update-retained-verb-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigateway-method-mock-in-place-update-retained-verb-replacement-then-not-found"
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
#: API Gateway's refusal of a method that no longer exists on an existing resource.
_METHOD_GONE = (_NOT_FOUND_CODE, "Invalid Method identifier specified")
_REQUEST_TEMPLATES = {"application/json": '{"statusCode": 200}'}


def _template(api_name: str, verb: str | None, greeting: str) -> str:
    """A REST API; with *verb*, a MOCK method on its root answering *greeting*."""
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
    if verb is not None:
        resources["Method"] = {
            "Type": "AWS::ApiGateway::Method",
            # HttpMethod is create-only, so changing it replaces the method.
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "ResourceId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                "HttpMethod": verb,
                "AuthorizationType": "AWS_IAM",
                "Integration": {
                    "Type": "MOCK",
                    "RequestTemplates": _REQUEST_TEMPLATES,
                    "IntegrationResponses": [
                        {"StatusCode": "200", "ResponseTemplates": _response(greeting)}
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


def _response(greeting: str) -> dict:
    return {"application/json": json.dumps({"greeting": greeting})}


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
    """A CloudFormation MOCK method has the template's integration and answers TestInvokeMethod.

    A response-template change updates it in place; an HttpMethod change under UpdateReplacePolicy
    Retain keeps the old verb answering; removal and delete answer NotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-method.html
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-cfnmeth-")
    stack_name = ctx.unique_name("sim2real-cfnmeth-stack-")
    ref = {"stack": stack_name}

    # The retained method lives inside the stack's API, which the stack delete removes.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, API Gateway's view, and the method answering
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(api_name, "GET", "hello"), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    api_id, get_id = ids["Api"], ids["Method"]
    root_id = _outputs(stack)["RootResourceId"]
    _assert_method(apigw, api_id, root_id, "GET", "hello")
    _assert_test_invoke(apigw, api_id, root_id, "GET", "hello")

    # ---- 2. in-place: a new MOCK response template on the same method
    events = _update(ctx, cfn, ref, _template(api_name, "GET", "bonjour"))
    assert _physical_ids(cfn, ref["stack"])["Method"] == get_id, "an in-place update keeps GET"
    _assert_in_place(_rows(events, set(), "Method"), get_id, "Method")
    _assert_method(apigw, api_id, root_id, "GET", "bonjour")
    _assert_test_invoke(apigw, api_id, root_id, "GET", "bonjour")

    # ---- 3. replacement under UpdateReplacePolicy Retain: a POST method, the GET method kept
    events = _update(ctx, cfn, ref, _template(api_name, "POST", "hola"))
    post_id = _physical_ids(cfn, ref["stack"])["Method"]
    assert post_id != get_id, f"an HttpMethod change must replace the method: {post_id!r}"
    _assert_replaced_and_retained(_rows(events, set(), "Method"), get_id, post_id, "Method")
    _assert_method(apigw, api_id, root_id, "POST", "hola")
    _assert_test_invoke(apigw, api_id, root_id, "POST", "hola")
    _assert_method(apigw, api_id, root_id, "GET", "bonjour")
    _assert_test_invoke(apigw, api_id, root_id, "GET", "bonjour")

    # ---- 4. removal from the template: CloudFormation deletes POST, the retained GET stays
    events = _update(ctx, cfn, ref, _template(api_name, None, ""))
    deleted = [s for s, _, pid in _rows(events, set(), "Method") if pid == post_id]
    assert deleted == ["DELETE_IN_PROGRESS", "DELETE_COMPLETE"], f"POST removal events: {deleted!r}"
    got = _wait_error(
        ctx,
        lambda: apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="POST"),
        _NOT_FOUND_CODE,
        "POST /",
    )
    assert got == _METHOD_GONE, f"GetMethod POST after removal answered {got!r}"
    _assert_test_invoke(apigw, api_id, root_id, "GET", "bonjour")

    # ---- 5. delete: API Gateway no longer knows the stack's API
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: apigw.get_rest_api(restApiId=api_id), _NOT_FOUND_CODE, f"REST API {api_id}"
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(account=ctx.account, api_id=api_id))
    assert got == want, f"GetRestApi after the stack delete answered {got!r}, expected {want!r}"


def _assert_method(apigw, api_id: str, root_id: str, verb: str, greeting: str) -> None:
    """GetMethod reports the template's verb, authorization and MOCK integration exactly."""
    method = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod=verb)
    integration = method.get("methodIntegration", {})
    got = {
        "httpMethod": method.get("httpMethod"),
        "authorizationType": method.get("authorizationType"),
        "type": integration.get("type"),
        "requestTemplates": integration.get("requestTemplates"),
        "responseTemplates": integration.get("integrationResponses", {})
        .get("200", {})
        .get("responseTemplates"),
    }
    want = {
        "httpMethod": verb,
        "authorizationType": "AWS_IAM",
        "type": "MOCK",
        "requestTemplates": _REQUEST_TEMPLATES,
        "responseTemplates": _response(greeting),
    }
    assert got == want, f"GetMethod {verb} /: {got!r}, expected {want!r}"


def _assert_test_invoke(apigw, api_id: str, root_id: str, verb: str, greeting: str) -> None:
    """TestInvokeMethod runs the MOCK integration and returns its response template."""
    resp = apigw.test_invoke_method(restApiId=api_id, resourceId=root_id, httpMethod=verb)
    got = (resp.get("status"), json.loads(resp.get("body") or "null"))
    assert got == (200, {"greeting": greeting}), (
        f"TestInvokeMethod {verb} / answered {got!r}, expected (200, greeting {greeting!r})"
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


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


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
