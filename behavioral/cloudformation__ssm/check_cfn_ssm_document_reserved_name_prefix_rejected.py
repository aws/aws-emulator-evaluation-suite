"""cfn-ssm-document-reserved-name-prefix-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

CHECK = "cfn-ssm-document-reserved-name-prefix-rejected"
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


def _content(message: str) -> dict:
    return {
        "schemaVersion": "2.2",
        "description": "sim2real reserved-name-prefix test document",
        "mainSteps": [
            {
                "action": "aws:runShellScript",
                "name": "runShellScript",
                "inputs": {"runCommand": [f"echo {message}"]},
            }
        ],
    }


def _template(name: str, message: str) -> str:
    return json.dumps(
        {
            "Resources": {
                "Doc": {
                    "Type": "AWS::SSM::Document",
                    "Properties": {
                        "Name": name,
                        "DocumentType": "Command",
                        "Content": _content(message),
                    },
                }
            }
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


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
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


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
        timeout_s=180.0,
        interval_s=5.0,
        description=f"stack {stack_name} creation",
    )
    return stack_id, status


def _events(cfn, stack_id: str) -> list:
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]]


def _create_failed_reason(reserved_name: str) -> re.Pattern:
    """The resource handler's InvalidRequest reason for a reserved document-name prefix, with
    its Request ID and RequestToken UUIDs and its SDK attempt count masked."""
    return re.compile(
        r'^Resource handler returned message: "Invalid request provided: Invalid document name '
        + re.escape(reserved_name)
        + r"  \(Service: Ssm, Status Code: 400, Request ID: "
        + _UUID
        + r"\) \(SDK Attempt Count: [0-9]+\)\" \(RequestToken: "
        + _UUID
        + r", HandlerErrorCode: InvalidRequest\)$"
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A stack declaring an AWS::SSM::Document whose Name starts with the reserved prefix "aws"
    rolls back with InvalidRequest and no document; the same template with a Name without that
    prefix reaches CREATE_COMPLETE with an Active document holding the template's content."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    reserved_name = "aws-" + ctx.unique_name("sim2real-behav-ssmdoc-bad-")
    bad_stack = ctx.unique_name("sim2real-behav-ssmdoc-bad-stack-")
    bad_id, status = _create(ctx, cfn, bad_stack, _template(reserved_name, "sim2real-bad"))
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    reasons = [
        e.get("ResourceStatusReason", "")
        for e in _events(cfn, bad_id)
        if e.get("LogicalResourceId") == "Doc" and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert len(reasons) == 1 and _create_failed_reason(reserved_name).match(reasons[0]), (
        f"expected exactly one Doc CREATE_FAILED naming the reserved document name, got {reasons!r}"
    )

    code, message = _error(lambda: ssm.get_document(Name=reserved_name))
    assert (code, message) == (
        "InvalidDocument",
        f"Document with name {reserved_name} does not exist.",
    ), f"unexpected not-found error: {(code, message)!r}"

    # Positive control: the same template with a Name outside the reserved prefix deploys.
    good_name = ctx.unique_name("sim2real-behav-ssmdoc-ok-")
    good_stack = ctx.unique_name("sim2real-behav-ssmdoc-ok-stack-")
    _, status = _create(ctx, cfn, good_stack, _template(good_name, "sim2real-ok"))
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"
    got = ssm.get_document(Name=good_name)
    assert (got["Name"], got["Status"], got["DocumentType"]) == (good_name, "Active", "Command"), (
        f"unexpected GetDocument for the control: {got!r}"
    )
    assert json.loads(got["Content"]) == _content("sim2real-ok"), (
        f"unexpected control document content: {got['Content']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
