"""cfn-ssm-association-invalid-schedule-expression-rejected-rolls-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-association-invalid-schedule-expression-rejected-rolls-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_CREATE_TERMINAL = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}
_DELETE_TERMINAL = {"DELETE_COMPLETE", "DELETE_FAILED"}
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_BAD_SCHEDULE = "not-a-valid-expression"
_GOOD_SCHEDULE = "rate(7 days)"
_REJECTED = (
    "Invalid request provided: Only schedule expressions of type rate, cron, and at are "
    "supported. (Service: Ssm, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(tag_key: str, tag_value: str, schedule: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Association": {
                    "Type": "AWS::SSM::Association",
                    "Properties": {
                        "Name": "AWS-RunShellScript",
                        "Parameters": {"commands": ["echo sim2real"]},
                        "Targets": [{"Key": f"tag:{tag_key}", "Values": [tag_value]}],
                        "ScheduleExpression": schedule,
                    },
                },
            },
            "Outputs": {"AssociationRef": {"Value": {"Ref": "Association"}}},
        }
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack_status(cfn, stack_id: str) -> str:
    """The stack's status read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return "DELETE_COMPLETE"
        raise


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    status = _stack_status(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status != "DELETE_IN_PROGRESS":
        _poll_until(
            ctx,
            lambda: _stack_status(cfn, stack_id),
            lambda s: not s.endswith("_IN_PROGRESS"),
            timeout_s=300.0,
            description=f"stack {stack_id} settling before delete",
        )
    cfn.delete_stack(StackName=stack_id)
    status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, stack_id),
        lambda s: s in _DELETE_TERMINAL,
        timeout_s=300.0,
        interval_s=5.0,
        description=f"delete stack {stack_id}",
    )
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {status!r}, not DELETE_COMPLETE")


def _create(ctx, cfn, stack_name: str, template: str) -> tuple[str, str]:
    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=template)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))
    status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, stack_id),
        lambda s: s in _CREATE_TERMINAL,
        timeout_s=300.0,
        interval_s=5.0,
        description=f"stack {stack_name} creation",
    )
    return stack_id, status


def _events(cfn, stack_id: str) -> list:
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]]


def _handler_reason(reason: str) -> tuple[str, str]:
    """(message, HandlerErrorCode) of a resource-handler reason, masking only the Request ID
    and the SDK attempt count."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    message = re.sub(r"Request ID: [^,;)]+", "Request ID: <id>", m["message"])
    message = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", message)
    return message, m["code"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack declaring an AWS::SSM::Association with a malformed ScheduleExpression rolls back
    with SSM's exact refusal and no association; the same template with rate(7 days) deploys
    and SSM stores that schedule."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    tag_key = "Sim2realAssocSchedule"

    bad_stack = ctx.unique_name("sim2real-behav-assocsched-bad-stack-")
    bad_template = _template(
        tag_key, ctx.unique_name("sim2real-behav-assocsched-bad-"), _BAD_SCHEDULE
    )
    bad_id, status = _create(ctx, cfn, bad_stack, bad_template)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    reasons = [
        e.get("ResourceStatusReason", "")
        for e in _events(cfn, bad_id)
        if e.get("LogicalResourceId") == "Association"
        and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, f"expected exactly one Association CREATE_FAILED row, got {reasons!r}"
    got = _handler_reason(reasons[0])
    assert got == _REJECTED, (
        f"the Association CREATE_FAILED reason was {got!r}, expected {_REJECTED!r}"
    )

    assoc_resources = [
        r
        for r in cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
        if r["LogicalResourceId"] == "Association"
    ]
    assert len(assoc_resources) == 1, (
        f"expected exactly one Association resource, got {assoc_resources!r}"
    )
    assert (assoc_resources[0]["ResourceStatus"], assoc_resources[0].get("PhysicalResourceId")) in (
        ("DELETE_COMPLETE", None),
        ("DELETE_COMPLETE", ""),
    ), f"expected a rolled-back Association with no physical id, got {assoc_resources[0]!r}"

    # Positive control: the same template with a rate expression deploys.
    good_stack = ctx.unique_name("sim2real-behav-assocsched-ok-stack-")
    good_tag = ctx.unique_name("sim2real-behav-assocsched-ok-")
    good_id, status = _create(ctx, cfn, good_stack, _template(tag_key, good_tag, _GOOD_SCHEDULE))
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=good_id)["Stacks"][0].get("Outputs", [])
    }
    association = ssm.describe_association(AssociationId=outputs["AssociationRef"])[
        "AssociationDescription"
    ]
    got = (association["Name"], association["ScheduleExpression"], association["Targets"])
    want = ("AWS-RunShellScript", _GOOD_SCHEDULE, [{"Key": f"tag:{tag_key}", "Values": [good_tag]}])
    assert got == want, f"the control association reads back {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
