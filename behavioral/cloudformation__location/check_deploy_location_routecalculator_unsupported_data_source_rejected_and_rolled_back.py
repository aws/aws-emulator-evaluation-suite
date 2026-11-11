"""deploy-location-routecalculator-unsupported-data-source-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-location-routecalculator-unsupported-data-source-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "location"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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

_BAD_DATA_SOURCE = "Bing"
_GOOD_DATA_SOURCE = "Esri"
_REJECTED = (
    "Invalid request provided: 'DataSource' must be one of Esri, Grab, Here. "
    "(Service: Location, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(calculator_name: str, tag_value: str, *, data_source: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Calculator": {
                "Type": "AWS::Location::RouteCalculator",
                "Properties": {"CalculatorName": calculator_name, "DataSource": data_source,
                                "Tags": t},
            },
        },
        "Outputs": {
            "CalculatorName": {"Value": {"Ref": "Calculator"}},
            "CalculatorArn": {"Value": {"Fn::GetAtt": ["Calculator", "Arn"]}},
        },
    })


def _tags_of(loc, arn: str) -> dict:
    """The resource's tags at Location, without CloudFormation's own aws: system tags."""
    found = loc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    return {k: v for k, v in found.items() if not k.startswith("aws:")}


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Location::RouteCalculator with an unsupported DataSource is
    forwarded to Location, refused with its own exact error, and the stack rolls back
    without ever creating the calculator; a supported DataSource still succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-location-routecalculator.html
    """
    loc = ctx.client("location")
    cfn = ctx.client("cloudformation")
    bad_stack = ctx.unique_name("sim2real-locroutecalcbad-")
    bad_calc_name = ctx.unique_name("sim2real-loc-calc-")

    bad_id = create_stack(
        ctx, cfn, bad_stack, _template(bad_calc_name, CHECK, data_source=_BAD_DATA_SOURCE),
    )

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Calculator"), ctx.account)
    assert got == _REJECTED, f"expected the failure reason {_REJECTED!r}, got {got!r}"

    # The rollback, not the check's own delete, leaves no calculator behind.
    bad_absent = ("ResourceNotFoundException", f"Route calculator not found: {bad_calc_name}.")
    expect_error(lambda: loc.describe_route_calculator(CalculatorName=bad_calc_name), *bad_absent)
    delete_stack(cfn, bad_id)

    # Positive control: the identical mechanism with a supported DataSource still succeeds.
    good_stack = ctx.unique_name("sim2real-locroutecalcgood-")
    good_calc_name = ctx.unique_name("sim2real-loc-calc-")
    good_id = create_stack(
        ctx, cfn, good_stack, _template(good_calc_name, CHECK, data_source=_GOOD_DATA_SOURCE),
    )
    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    control_out = stack_outputs(cfn, good_id)
    assert control_out["CalculatorName"] == good_calc_name, (
        f"expected Ref on the control Calculator to equal {good_calc_name!r}, stack reports "
        f"{control_out['CalculatorName']!r}"
    )
    control = loc.describe_route_calculator(CalculatorName=good_calc_name)
    assert control["CalculatorName"] == control_out["CalculatorName"], (
        f"expected DescribeRouteCalculator CalculatorName {good_calc_name!r}, Location reports "
        f"{control['CalculatorName']!r}"
    )
    assert control["CalculatorArn"] == control_out["CalculatorArn"], (
        f"expected DescribeRouteCalculator CalculatorArn to equal the GetAtt "
        f"{control_out['CalculatorArn']!r}, Location reports {control['CalculatorArn']!r}"
    )
    assert control["DataSource"] == _GOOD_DATA_SOURCE, (
        f"expected the control calculator's DataSource {_GOOD_DATA_SOURCE!r}, Location reports "
        f"{control['DataSource']!r}"
    )
    control_tags = _tags_of(loc, control["CalculatorArn"])
    want_tags = {"sim2real": good_stack, "sim2real-check": CHECK}
    assert control_tags == want_tags, (
        f"expected the stack and declared tags {want_tags!r}, Location reports {control_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
