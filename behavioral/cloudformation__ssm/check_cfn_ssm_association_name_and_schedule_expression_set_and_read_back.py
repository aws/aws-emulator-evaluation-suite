"""cfn-ssm-association-name-and-schedule-expression-set-and-read-back."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-association-name-and-schedule-expression-set-and-read-back"
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


def _template(association_name: str, schedule_expression: str, tag_key: str, tag_value: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Association": {
                    "Type": "AWS::SSM::Association",
                    "Properties": {
                        "Name": "AWS-RunShellScript",
                        "AssociationName": association_name,
                        "ScheduleExpression": schedule_expression,
                        "Parameters": {"commands": ["echo sim2real-assocprop"]},
                        "Targets": [{"Key": f"tag:{tag_key}", "Values": [tag_value]}],
                    },
                },
            },
            "Outputs": {
                "AssociationId": {"Value": {"Fn::GetAtt": ["Association", "AssociationId"]}},
            },
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


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack's AWS::SSM::Association AssociationName and ScheduleExpression are stored exactly
    as declared, and its Fn::GetAtt AssociationId names the one association ListAssociations
    finds under that name."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack_name = ctx.unique_name("sim2real-behav-assocprop-stack-")
    association_name = ctx.unique_name("sim2real-behav-assocprop-name-")
    tag_key = "Sim2realAssocPropTarget"
    tag_value = ctx.unique_name("sim2real-behav-assocprop-tag-")
    schedule_expression = "rate(7 days)"

    template = _template(association_name, schedule_expression, tag_key, tag_value)
    stack_id, status = _create(ctx, cfn, stack_name, template)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack_name} reached {status!r}, expected CREATE_COMPLETE"
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])
    }
    association_id = outputs["AssociationId"]

    pages = ssm.get_paginator("list_associations").paginate(
        AssociationFilterList=[{"key": "AssociationName", "value": association_name}]
    )
    listed = [a["AssociationId"] for page in pages for a in page["Associations"]]
    assert listed == [association_id], (
        f"ListAssociations by name {association_name!r} found {listed!r}, expected the stack's "
        f"Fn::GetAtt output {[association_id]!r}"
    )

    description = ssm.describe_association(AssociationId=association_id)["AssociationDescription"]
    got = (
        description["Name"],
        description["AssociationName"],
        description["ScheduleExpression"],
        description["Targets"],
    )
    want = (
        "AWS-RunShellScript",
        association_name,
        schedule_expression,
        [{"Key": f"tag:{tag_key}", "Values": [tag_value]}],
    )
    assert got == want, f"DescribeAssociation reads back {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
