"""deploy-group-via-cloudformation-invalid-filter-expression-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-group-via-cloudformation-invalid-filter-expression-rejected"
GROUP = "deploy"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AWS::XRay::Group with an invalid FilterExpression rolls the stack back with an XRay 400
    on TraceGroup and the group never exists; a valid-expression stack deploys and persists."""
    xray = ctx.client("xray")
    cfn = ctx.client("cloudformation")

    # GroupName is capped at 32 chars by CloudFormation; ctx.unique_name appends a
    # 12-hex-char suffix, so the prefix itself must stay <= 20 chars.
    bad_group_name = ctx.unique_name("sim2real-badgrp-")
    bad_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TraceGroup": {
                "Type": "AWS::XRay::Group",
                "Properties": {
                    "GroupName": bad_group_name,
                    # Unbalanced parenthesis: not a valid X-Ray filter expression.
                    "FilterExpression": '(annotation.scenario = "x"',
                },
            }
        },
    }
    bad_stack = ctx.unique_name("sim2real-xray-badstack-")
    cfn.create_stack(StackName=bad_stack, TemplateBody=json.dumps(bad_template))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=bad_stack))

    terminal_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=bad_stack)["Stacks"][0]["StackStatus"],
        lambda status: status
        in (
            "CREATE_COMPLETE",
            "CREATE_FAILED",
            "ROLLBACK_COMPLETE",
            "ROLLBACK_FAILED",
        ),
        timeout_s=180.0,
        interval_s=5.0,
    )
    # The stack is created with the default OnFailure=ROLLBACK, so a refused resource rolls the
    # stack back to ROLLBACK_COMPLETE.
    assert terminal_status == "ROLLBACK_COMPLETE", (
        f"stack with an invalid FilterExpression reached {terminal_status} "
        "instead of rolling back"
    )
    rollback_reason = _event_reason(cfn, bad_stack, bad_stack, "ROLLBACK_IN_PROGRESS")
    assert rollback_reason == (
        "The following resource(s) failed to create: [TraceGroup]. Rollback requested by user."
    ), f"the rollback must name TraceGroup as the resource that failed, got {rollback_reason!r}"

    # Naming the upstream service distinguishes an XRay rejection from CFN template validation.
    # The reason embeds per-call XRay Request ID and CFN RequestToken, so match substrings only.
    resource_reason = _event_reason(cfn, bad_stack, "TraceGroup", "CREATE_FAILED")
    assert (
        resource_reason is not None
        and "Service: XRay" in resource_reason
        and "Status Code: 400" in resource_reason
    ), (
        "expected the TraceGroup resource's own failure reason to name a 400 "
        f"from the XRay service, got {resource_reason!r}"
    )

    missing = _client_error(lambda: xray.get_group(GroupName=bad_group_name))
    assert (missing.get("Code"), missing.get("Message")) == (
        "InvalidRequestException", "Group not found"
    ), f"expected the never-created group to be unknown, got {missing!r}"

    good_group_name = ctx.unique_name("sim2real-okgrp-")
    good_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TraceGroup": {
                "Type": "AWS::XRay::Group",
                "Properties": {
                    "GroupName": good_group_name,
                    "FilterExpression": 'annotation.scenario = "ok"',
                },
            }
        },
    }
    good_stack = ctx.unique_name("sim2real-xray-goodstack-")
    cfn.create_stack(StackName=good_stack, TemplateBody=json.dumps(good_template))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=good_stack))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=good_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 200}
    )
    good_group = xray.get_group(GroupName=good_group_name)["Group"]
    assert good_group["FilterExpression"] == 'annotation.scenario = "ok"', (
        "expected the identically-shaped stack's group to persist the valid "
        f"FilterExpression, got {good_group['FilterExpression']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _event_reason(cfn, stack_name: str, logical_id: str, status: str) -> str | None:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for event in events:
        if (
            event.get("LogicalResourceId") == logical_id
            and event.get("ResourceStatus") == status
        ):
            return event.get("ResourceStatusReason")
    return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
