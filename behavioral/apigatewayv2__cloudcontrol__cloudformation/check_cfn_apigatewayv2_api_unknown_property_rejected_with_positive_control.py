"""cfn-apigatewayv2-api-unknown-property-rejected-with-positive-control."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-apigatewayv2-api-unknown-property-rejected-with-positive-control"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudcontrol", "cloudformation"]

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_DELETE_TERMINAL = {"DELETE_COMPLETE", "DELETE_FAILED"}
_SCHEMA_FAILURE_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)
_VALIDATION_ROWS = [(
    "Api", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "Unsupported property [ThisPropertyDoesNotExist]",
    "/Resources/Api/Properties/ThisPropertyDoesNotExist",
)]
_ROUTE_SELECTION = "$request.method $request.path"


def _poll(cf, stack_id: str, terminal: set, *, timeout_s: float = 240.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _failure_reason(cf, stack_id: str, logical_id: str) -> str:
    """Reason of the stack's own CREATE_FAILED row (LogicalResourceId is the stack name)."""
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if (event["ResourceStatus"] == "CREATE_FAILED"
                    and event["LogicalResourceId"] == logical_id
                    and event.get("ResourceStatusReason")):
                return event["ResourceStatusReason"]
    raise AssertionError(f"no CREATE_FAILED event for {logical_id!r} carrying a reason in {stack_id!r}")


def _validation_errors(cf, stack_id: str) -> list[tuple]:
    """``(logical id, name, status, mode, reason, path)`` of every VALIDATION_ERROR event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cf.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
             e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _api_names(apigw, want: str) -> set:
    names = set()
    for page in apigw.get_paginator("get_apis").paginate():
        for item in page["Items"]:
            if item["Name"] == want:
                names.add(item["Name"])
    return names


def _template(name: str, *, unknown: bool) -> str:
    props = {"Name": name, "ProtocolType": "HTTP", "RouteSelectionExpression": _ROUTE_SELECTION}
    if unknown:
        props["ThisPropertyDoesNotExist"] = 1
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Api": {"Type": "AWS::ApiGatewayV2::Api", "Properties": props}},
        "Outputs": {"ApiRef": {"Value": {"Ref": "Api"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unknown property on a CFN AWS::ApiGatewayV2::Api fails early validation at its own path
    and creates no api, while the same template without it deploys with every property in place.
    """
    cf = ctx.client("cloudformation")
    apigw = ctx.client("apigatewayv2")
    cc = ctx.client("cloudcontrol")

    bad_name = ctx.unique_name("sim2real-behav-apigwneg-")
    bad_stack = ctx.unique_name("sim2real-behav-apigwnegstack-")
    bad_stack_id = cf.create_stack(
        StackName=bad_stack, TemplateBody=_template(bad_name, unknown=True),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, bad_stack_id))

    bad_status = _poll(cf, bad_stack_id, _CREATE_TERMINAL)
    assert bad_status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {bad_status!r}"
    reason = _failure_reason(cf, bad_stack_id, bad_stack)
    assert reason == _SCHEMA_FAILURE_REASON, (
        f"expected the resource-schema failure reason {_SCHEMA_FAILURE_REASON!r}, got {reason!r}"
    )
    rows = _validation_errors(cf, bad_stack_id)
    assert rows == _VALIDATION_ROWS, f"VALIDATION_ERROR rows expected {_VALIDATION_ROWS!r}, got {rows!r}"

    found = _api_names(apigw, bad_name)
    assert found == set(), (
        f"the rolled-back stack must have created no api named {bad_name!r}, found {found!r}"
    )

    # Positive control: the same template, minus the unknown property, reaches CREATE_COMPLETE.
    good_name = ctx.unique_name("sim2real-behav-apigwctl-")
    good_stack = ctx.unique_name("sim2real-behav-apigwctlstack-")
    good_stack_id = cf.create_stack(
        StackName=good_stack, TemplateBody=_template(good_name, unknown=False),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, good_stack_id))

    good_status = _poll(cf, good_stack_id, _CREATE_TERMINAL)
    assert good_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {good_status!r}"

    api_id = {o["OutputKey"]: o["OutputValue"]
              for o in cf.describe_stacks(StackName=good_stack_id)["Stacks"][0]["Outputs"]}["ApiRef"]
    listed = [item for page in apigw.get_paginator("get_apis").paginate()
              for item in page["Items"] if item["Name"] == good_name]
    assert [item["ApiId"] for item in listed] == [api_id], (
        f"GetApis lists {len(listed)} api(s) named {good_name!r}; Ref must be the one api's ApiId"
    )
    live = apigw.get_api(ApiId=api_id)
    got = (live["Name"], live["ProtocolType"], live["RouteSelectionExpression"])
    want = (good_name, "HTTP", _ROUTE_SELECTION)
    assert got == want, f"GetApi (Name, ProtocolType, RouteSelectionExpression) expected {want!r}, got {got!r}"

    cc_props = json.loads(cc.get_resource(TypeName="AWS::ApiGatewayV2::Api", Identifier=api_id)[
        "ResourceDescription"]["Properties"])
    got_cc = (cc_props.get("ApiId"), cc_props.get("Name"), cc_props.get("ProtocolType"))
    assert got_cc == (api_id, good_name, "HTTP"), (
        f"Cloud Control's model (ApiId, Name, ProtocolType) expected "
        f"{(api_id, good_name, 'HTTP')!r}, got {got_cc!r}"
    )


def _delete_stack(cf, stack_id: str) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _poll(cf, stack_id, _DELETE_TERMINAL)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} ended {status!r}, expected DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
