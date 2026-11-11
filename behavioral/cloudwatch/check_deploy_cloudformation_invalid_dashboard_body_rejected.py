"""deploy-cloudformation-invalid-dashboard-body-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "deploy-cloudformation-invalid-dashboard-body-rejected"
GROUP = "deploy"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A malformed dashboard body is rejected by PutDashboard with InvalidParameterInput, and via
    CloudFormation the stack ends CREATE_FAILED with no dashboard created.
    A valid CloudFormation-deployed dashboard succeeds and round-trips its body."""
    cw = ctx.client("cloudwatch")
    cfn = ctx.client("cloudformation")

    bad_dashboard_name = ctx.unique_name("Sim2RealBehavBadDash")
    bad_body = "{ this is not valid dashboard json ]"

    # (a) exact error code: calling CloudWatch directly with the malformed body.
    code, message = _client_error(
        lambda: cw.put_dashboard(DashboardName=bad_dashboard_name, DashboardBody=bad_body)
    )
    assert code == "InvalidParameterInput", code
    expected_message = "The field DashboardBody must be a valid JSON object"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Same malformed body, driven through CloudFormation: the stack must roll back
    # rather than reach CREATE_COMPLETE.
    bad_stack_name = ctx.unique_name("sim2real-behav-badstack-")
    bad_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "BadDashboard": {
                "Type": "AWS::CloudWatch::Dashboard",
                "Properties": {
                    "DashboardName": bad_dashboard_name,
                    "DashboardBody": bad_body,
                },
            }
        },
    }
    cfn.create_stack(
        StackName=bad_stack_name, TemplateBody=json.dumps(bad_template), OnFailure="DO_NOTHING"
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=bad_stack_name))

    stack = _poll_until(
        lambda: cfn.describe_stacks(StackName=bad_stack_name)["Stacks"][0],
        lambda s: s["StackStatus"] in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED", "ROLLBACK_FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    # OnFailure=DO_NOTHING: the stack stops at CREATE_FAILED and names the failed resource.
    assert stack["StackStatus"] == "CREATE_FAILED", stack["StackStatus"]
    expected_reason = "The following resource(s) failed to create: [BadDashboard]. "
    assert stack.get("StackStatusReason") == expected_reason, (
        f"expected StackStatusReason {expected_reason!r}, got {stack.get('StackStatusReason')!r}"
    )

    # (b) effect absent: the invalid dashboard was never actually created.
    not_found_code, not_found_message = _client_error(
        lambda: cw.get_dashboard(DashboardName=bad_dashboard_name)
    )
    assert not_found_code == "ResourceNotFound", not_found_code
    expected_not_found = f"Dashboard {bad_dashboard_name} does not exist"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # (c) positive control: a valid dashboard deployed via CloudFormation is retrievable.
    good_dashboard_name = ctx.unique_name("Sim2RealBehavGoodDash")
    good_body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 3,
                "height": 3,
                "properties": {"markdown": "sim2real-behav-control"},
            }
        ]
    }
    good_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "GoodDashboard": {
                "Type": "AWS::CloudWatch::Dashboard",
                "Properties": {
                    "DashboardName": good_dashboard_name,
                    "DashboardBody": json.dumps(good_body),
                },
            }
        },
    }
    good_stack_name = _deploy_cfn(ctx, good_template)
    assert good_stack_name, "expected _deploy_cfn to return a non-empty stack name"
    good_resp = cw.get_dashboard(DashboardName=good_dashboard_name)
    actual_body = json.loads(good_resp["DashboardBody"])
    assert actual_body == good_body, f"expected dashboard body {good_body!r}, got {actual_body!r}"


def _deploy_cfn(ctx: Any, template: dict[str, Any]) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return stack_name


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    over-permissive target cannot pass as a mere error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
