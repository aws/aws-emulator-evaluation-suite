"""deploy-apigateway-usage-plan-invalid-quota-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-usage-plan-invalid-quota-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cloudformation"]


def _template(plan_name: str, limit: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SimPlan": {
                "Type": "AWS::ApiGateway::UsagePlan",
                "Properties": {
                    "UsagePlanName": plan_name,
                    "Quota": {"Limit": limit, "Period": "DAY"},
                    "Throttle": {"RateLimit": 10.0, "BurstLimit": 5},
                },
            }
        },
        "Outputs": {"PlanId": {"Value": {"Ref": "SimPlan"}}},
    })


_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _validation_errors(cfn, stack_name: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason, path)`` of each VALIDATION_ERROR operation event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"),
                    e.get("ValidationPath"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _plan_names(apigw) -> set:
    return {p["name"] for page in apigw.get_paginator("get_usage_plans").paginate() for p in page["items"]}


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::ApiGateway::UsagePlan with a negative Quota.Limit fails pre-deployment property
    validation, so the stack rolls back with no usage plan; the same template with a valid limit
    deploys, reads back, and its plan is NotFoundException after the stack delete."""
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    stack_name = ctx.unique_name("sim2real-cfn-badusageplan-")
    plan_name = ctx.unique_name("sim2real-badusageplan-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(plan_name, -5),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    status = _wait_terminal(cfn, stack_name, timeout_s=300.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"expected the stack to roll back on the bad quota, ended in {status!r}"
    )
    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name)
              for e in page["StackEvents"]]
    stack_failed = [e.get("ResourceStatusReason") for e in events
                    if e["LogicalResourceId"] == stack_name and e["ResourceStatus"] == "CREATE_FAILED"]
    assert stack_failed == [_STACK_REASON], (
        f"the stack's CREATE_FAILED reasons were {stack_failed!r}, expected [{_STACK_REASON!r}]"
    )
    found = _validation_errors(cfn, stack_name)
    want = [(
        "SimPlan", "AWS::ApiGateway::UsagePlan", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "#/Quota/Limit: -5 is not greater or equal to 0", "/Resources/SimPlan/Properties/Quota/Limit",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert resources == [], f"a stack rejected before provisioning reports resources {resources!r}"

    # Effect absent: no usage plan with this name exists in the account.
    assert plan_name not in _plan_names(apigw), f"expected {plan_name!r} absent, found it among usage plans"

    _delete_stack(ctx, stack_name)
    code, message = _error(lambda: cfn.describe_stacks(StackName=stack_name))
    assert (code, message) == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
        f"DescribeStacks of the deleted rolled-back stack answered {(code, message)!r}"
    )

    # Positive control: the same template with a valid quota deploys through CloudFormation.
    good_stack = ctx.unique_name("sim2real-cfn-goodusageplan-")
    good_name = ctx.unique_name("sim2real-goodusageplan-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_name, 1000),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, good_stack))
    status = _wait_terminal(cfn, good_stack, timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"the control stack settled at {status!r}, expected CREATE_COMPLETE"
    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=good_stack)["Stacks"][0].get("Outputs", [])}
    plan_id = outputs["PlanId"]
    fetched = apigw.get_usage_plan(usagePlanId=plan_id)
    assert fetched["name"] == good_name, f"control GetUsagePlan name was {fetched['name']!r}"
    assert fetched["quota"]["limit"] == 1000, f"expected quota.limit=1000, got {fetched['quota']}"

    _delete_stack(ctx, good_stack)
    code, message = _error(lambda: apigw.get_usage_plan(usagePlanId=plan_id))
    assert (code, message) == ("NotFoundException", "Invalid Usage Plan ID specified"), (
        f"GetUsagePlan after the control stack's delete answered {(code, message)!r}"
    )


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks every 2s until the stack settles; return the terminal status."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last.endswith("_COMPLETE") or last.endswith("_FAILED"):
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} never settled within {timeout_s}s (last={last!r})")


def _delete_stack(ctx, stack_name: str, timeout_s: float = 300.0) -> None:
    """Delete the stack and wait for it to vanish; DELETE_FAILED or the deadline raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        if not stacks:
            return
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
