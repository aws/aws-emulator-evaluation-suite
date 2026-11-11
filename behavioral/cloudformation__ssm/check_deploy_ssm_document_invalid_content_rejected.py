"""deploy-ssm-document-invalid-content-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

CHECK = "deploy-ssm-document-invalid-content-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within "
                          f"{timeout_s}s (last={last!r})")


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack declaring an AWS::SSM::Document whose Content is missing the required mainSteps
    rolls back with no document ever created, while a document SSM already accepted elsewhere
    stays Active and readable throughout.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    control_name = ctx.unique_name("sim2real-behav-ssmdoc-ctrl-")
    control_content = {
        "schemaVersion": "2.2",
        "description": "sim2real control document",
        "mainSteps": [
            {"action": "aws:runShellScript", "name": "runShellScript",
             "inputs": {"runCommand": ["echo sim2real-control"]}},
        ],
    }
    ssm.create_document(Name=control_name, DocumentType="Command",
                         Content=json.dumps(control_content))
    ctx.on_cleanup(lambda: ssm.delete_document(Name=control_name))
    control_before = ssm.get_document(Name=control_name)
    assert control_before["Status"] == "Active", (
        f"expected the control document to be Active, got {control_before['Status']!r}"
    )

    doc_name = ctx.unique_name("sim2real-behav-ssmdoc-bad-")
    stack_name = ctx.unique_name("sim2real-behav-ssmdoc-bad-stack-")
    bad_content = {"schemaVersion": "2.2", "description": "no mainSteps here"}
    template = json.dumps({
        "Resources": {
            "Doc": {
                "Type": "AWS::SSM::Document",
                "Properties": {
                    "Name": doc_name,
                    "DocumentType": "Command",
                    "Content": bad_content,
                },
            }
        }
    })
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _delete_stack_if_rolled_back(cfn, stack_name))
    status = _wait_terminal(cfn, stack_name)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    reasons = [
        e.get("ResourceStatusReason", "") for e in events
        if e.get("LogicalResourceId") == "Doc" and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert reasons and _create_failed_reason().match(reasons[0]), (
        f"expected the Doc resource's failure to name the missing mainSteps, got {reasons!r}"
    )

    code, message = _error(lambda: ssm.get_document(Name=doc_name))
    assert code == "InvalidDocument", f"expected InvalidDocument, got {code!r}"
    assert message == f"Document with name {doc_name} does not exist.", (
        f"unexpected not-found message: {message!r}"
    )

    control_after = ssm.get_document(Name=control_name)
    assert control_after["Status"] == "Active", (
        f"the control document must remain Active, got {control_after['Status']!r}"
    )


def _create_failed_reason() -> re.Pattern:
    """The resource handler's InvalidRequest reason for a missing-mainSteps document, with its
    two Request ID / RequestToken UUIDs graded by shape."""
    return re.compile(
        r'^Resource handler returned message: "Invalid request provided: Missing '
        r'"mainSteps" in the document\. \(Service: Ssm, Status Code: 400, Request ID: '
        + _UUID + r"\) \(SDK Attempt Count: 1\)\" \(RequestToken: " + _UUID
        + r", HandlerErrorCode: InvalidRequest\)$"
    )


def _delete_stack_if_rolled_back(cfn, stack_name: str) -> None:
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    if status == "ROLLBACK_COMPLETE":
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
