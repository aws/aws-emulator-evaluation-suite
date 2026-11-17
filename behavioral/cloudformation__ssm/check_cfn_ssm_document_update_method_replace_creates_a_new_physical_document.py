"""cfn-ssm-document-update-method-replace-creates-a-new-physical-document."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-document-update-method-replace-creates-a-new-physical-document"
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
_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}
_DELETE_TERMINAL = {"DELETE_COMPLETE", "DELETE_FAILED"}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack update to an unnamed AWS::SSM::Document with UpdateMethod Replace creates a new
    document under a new generated <stack>-Doc-<suffix> name at version 1, and deletes the old one.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack_name = ctx.unique_name("sim2real-behav-ssmdocrep-stack-")
    content_v1 = _content("sim2real-ssmdocrep-v1")
    content_v2 = _content("sim2real-ssmdocrep-v2")

    stack_id, status = _create(ctx, cfn, stack_name, _template(content_v1))
    assert status == "CREATE_COMPLETE", (
        f"stack {stack_name} reached {status!r}, expected CREATE_COMPLETE"
    )

    generated = re.compile(re.escape(f"{stack_name}-Doc-") + r"[A-Za-z0-9]{12}")
    doc_name_before = _doc_physical_id(cfn, stack_id)
    assert generated.fullmatch(doc_name_before), (
        f"the generated document name is {doc_name_before!r}, expected {stack_name}-Doc-<12 chars>"
    )
    before = ssm.describe_document(Name=doc_name_before)["Document"]
    assert before["DocumentVersion"] == "1", (
        f"a freshly created document's default DocumentVersion is {before['DocumentVersion']!r}, "
        f"expected '1'"
    )
    assert json.loads(ssm.get_document(Name=doc_name_before)["Content"]) == content_v1, (
        "the document's content after create does not match the declared Content"
    )

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(content_v2))
    status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, stack_id),
        lambda st: st in _UPDATE_TERMINAL,
        timeout_s=300.0,
        interval_s=5.0,
        description=f"stack {stack_name} update",
    )
    assert status == "UPDATE_COMPLETE", f"stack update reached {status!r}, expected UPDATE_COMPLETE"

    doc_name_after = _doc_physical_id(cfn, stack_id)
    assert generated.fullmatch(doc_name_after), (
        f"the replacement document name is {doc_name_after!r}, expected {stack_name}-Doc-<12 chars>"
    )
    assert doc_name_after != doc_name_before, (
        f"UpdateMethod Replace must create a new physical document, but the physical id stayed "
        f"{doc_name_after!r}"
    )

    after = ssm.describe_document(Name=doc_name_after)["Document"]
    assert after["DocumentVersion"] == "1", (
        f"the replacement document's default DocumentVersion is {after['DocumentVersion']!r}, "
        f"expected '1' -- a fresh document, not a new version of the old one"
    )
    assert json.loads(ssm.get_document(Name=doc_name_after)["Content"]) == content_v2, (
        "the replacement document's content does not match the updated template's Content"
    )

    got = _error(lambda: ssm.describe_document(Name=doc_name_before))
    want = ("InvalidDocument", f"Document with name {doc_name_before} does not exist.")
    assert got == want, f"the replaced-away document: {got!r}, expected {want!r}"


def _content(marker: str) -> dict:
    return {
        "schemaVersion": "2.2",
        "description": marker,
        "mainSteps": [
            {
                "action": "aws:runShellScript",
                "name": "runShellScript",
                "inputs": {"runCommand": [f"echo {marker}"]},
            },
        ],
    }


def _template(content: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Doc": {
                    "Type": "AWS::SSM::Document",
                    "Properties": {
                        "DocumentType": "Command",
                        "UpdateMethod": "Replace",
                        "Content": content,
                    },
                },
            },
        }
    )


def _doc_physical_id(cfn, stack_id: str) -> str:
    """The physical id of the stack's single Doc resource."""
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    ids = [r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == "Doc"]
    assert len(ids) == 1, f"expected exactly one Doc resource, got {ids!r}"
    return ids[0]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
