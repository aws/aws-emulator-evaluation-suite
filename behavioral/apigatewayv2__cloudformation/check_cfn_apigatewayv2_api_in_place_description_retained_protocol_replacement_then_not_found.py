"""cfn-apigatewayv2-api-in-place-description-retained-protocol-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigatewayv2-api-in-place-description-retained-protocol-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: API Gateway's refusal of an API that no longer exists, naming account and API id.
_NOT_FOUND_CODE = "NotFoundException"
_NOT_FOUND_MESSAGE = "Invalid API identifier specified {account}:{api_id}"
_HTTP_ROUTE_KEY = "GET /hello"
_HTTP_SELECTION = "$request.method $request.path"
_WS_SELECTION = "$request.body.action"
#: The HTTP integration's target; the API is never invoked, so nothing dials it.
_HTTP_URI = "https://example.com"


def _template(api_name: str, protocol: str, description: str) -> str:
    """An HTTP API with one HTTP_PROXY route, or a WebSocket API with a MOCK $default route."""
    api = {
        "Name": api_name,
        "ProtocolType": protocol,
        "Description": description,
        # No default execute-api endpoint: the API is never reachable publicly.
        "DisableExecuteApiEndpoint": True,
        "Tags": {"sim2real": CHECK},
    }
    if protocol == "HTTP":
        integration = {
            "IntegrationType": "HTTP_PROXY",
            "IntegrationMethod": "GET",
            "IntegrationUri": _HTTP_URI,
            "PayloadFormatVersion": "1.0",
        }
        route_key = _HTTP_ROUTE_KEY
    else:
        api["RouteSelectionExpression"] = _WS_SELECTION
        integration = {"IntegrationType": "MOCK"}
        route_key = "$default"
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Api": {
                    "Type": "AWS::ApiGatewayV2::Api",
                    # ProtocolType is create-only, so changing it replaces the API.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": api,
                },
                "Integration": {
                    "Type": "AWS::ApiGatewayV2::Integration",
                    "Properties": {"ApiId": {"Ref": "Api"}, **integration},
                },
                "Route": {
                    "Type": "AWS::ApiGatewayV2::Route",
                    "Properties": {
                        "ApiId": {"Ref": "Api"},
                        "RouteKey": route_key,
                        "Target": {"Fn::Join": ["/", ["integrations", {"Ref": "Integration"}]]},
                    },
                },
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation HTTP API reads back with the template's route wired to its integration.

    A Description change keeps the API; a ProtocolType change under UpdateReplacePolicy Retain
    creates a WebSocket API and keeps the HTTP one, emptied; delete: GetApi NotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html
    """
    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    api_name = ctx.unique_name("sim2real-cfnhttpapi-")
    stack_name = ctx.unique_name("sim2real-cfnhttpapi-stack-")
    ref = {"stack": stack_name}
    retained: dict[str, str] = {}

    # The replaced API is retained; teardown deletes it after the stack.
    ctx.on_cleanup(lambda: _delete_api(agw, retained.get("api")))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, API Gateway's view, the route and its integration
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(api_name, "HTTP", "first"), Tags=_TAGS
    )["StackId"]
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    http_id = ids["Api"]
    retained["api"] = http_id
    _assert_api(agw, http_id, api_name, "HTTP", _HTTP_SELECTION, "first")
    _assert_wiring(agw, http_id, ids, _HTTP_ROUTE_KEY, "HTTP_PROXY")

    # ---- 2. in-place: a new Description on the same API; its route and integration stay
    events = _update(ctx, cfn, ref, _template(api_name, "HTTP", "second"))
    assert _physical_ids(cfn, ref["stack"]) == ids, "an in-place update keeps every physical id"
    _assert_in_place(_rows(events, set(), "Api"), http_id, "Api")
    _assert_api(agw, http_id, api_name, "HTTP", _HTTP_SELECTION, "second")
    _assert_wiring(agw, http_id, ids, _HTTP_ROUTE_KEY, "HTTP_PROXY")

    # ---- 3. replacement under UpdateReplacePolicy Retain: a WebSocket API, the HTTP API kept
    events = _update(ctx, cfn, ref, _template(api_name, "WEBSOCKET", "second"))
    ws_ids = _physical_ids(cfn, ref["stack"])
    ws_id = ws_ids["Api"]
    assert ws_id != http_id, f"a ProtocolType change must replace the API: {ws_ids!r}"
    _assert_replaced_and_retained(_rows(events, set(), "Api"), http_id, ws_id, "Api")
    _assert_api(agw, ws_id, api_name, "WEBSOCKET", _WS_SELECTION, "second")
    _assert_wiring(agw, ws_id, ws_ids, "$default", "MOCK")
    # The route and integration moved with ApiId (not retained), so the HTTP API is kept empty.
    _assert_api(agw, http_id, api_name, "HTTP", _HTTP_SELECTION, "second")
    left = (agw.get_routes(ApiId=http_id)["Items"], agw.get_integrations(ApiId=http_id)["Items"])
    assert left == ([], []), f"the retained HTTP API must keep no routes or integrations: {left!r}"

    # ---- 4. delete: API Gateway no longer knows the stack's API; the retained one remains
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(ctx, lambda: agw.get_api(ApiId=ws_id), _NOT_FOUND_CODE, f"API {ws_id}")
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(account=ctx.account, api_id=ws_id))
    assert got == want, f"GetApi after the stack delete answered {got!r}, expected {want!r}"
    _assert_api(agw, http_id, api_name, "HTTP", _HTTP_SELECTION, "second")


def _assert_api(agw, api_id: str, name: str, protocol: str, selection: str, desc: str) -> None:
    """GetApi reports the template's name, protocol, selection expression and settings exactly."""
    api = agw.get_api(ApiId=api_id)
    got = {
        "ApiId": api.get("ApiId"),
        "Name": api.get("Name"),
        "ProtocolType": api.get("ProtocolType"),
        "RouteSelectionExpression": api.get("RouteSelectionExpression"),
        "Description": api.get("Description"),
        "DisableExecuteApiEndpoint": api.get("DisableExecuteApiEndpoint"),
        "sim2real tag": api.get("Tags", {}).get("sim2real"),
    }
    want = {
        "ApiId": api_id,
        "Name": name,
        "ProtocolType": protocol,
        "RouteSelectionExpression": selection,
        "Description": desc,
        "DisableExecuteApiEndpoint": True,
        "sim2real tag": CHECK,
    }
    assert got == want, f"GetApi {api_id}: {got!r}, expected {want!r}"


def _assert_wiring(agw, api_id: str, ids: dict, route_key: str, integration_type: str) -> None:
    """The API's only route has the template's key and targets its only integration."""
    routes = [
        (r.get("RouteId"), r.get("RouteKey"), r.get("Target"))
        for r in agw.get_routes(ApiId=api_id)["Items"]
    ]
    want_routes = [(ids["Route"], route_key, f"integrations/{ids['Integration']}")]
    assert routes == want_routes, f"GetRoutes {api_id}: {routes!r}, expected {want_routes!r}"
    integrations = agw.get_integrations(ApiId=api_id)["Items"]
    got = [(i.get("IntegrationId"), i.get("IntegrationType")) for i in integrations]
    assert got == [(ids["Integration"], integration_type)], (
        f"GetIntegrations {api_id}: {got!r}, expected one {integration_type} integration"
    )
    if integration_type == "HTTP_PROXY":
        detail = {k: integrations[0].get(k) for k in ("IntegrationMethod", "IntegrationUri")}
        want = {"IntegrationMethod": "GET", "IntegrationUri": _HTTP_URI}
        assert detail == want, f"the HTTP_PROXY integration reads back {detail!r}, not {want!r}"


def _delete_api(agw, api_id: str | None) -> None:
    if api_id is None:
        return
    try:
        agw.delete_api(ApiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND_CODE:
            raise


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
