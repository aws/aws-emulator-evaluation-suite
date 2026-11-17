"""cfn-ssm-document-update-method-newversion-keeps-name-and-adds-a-version."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-document-update-method-newversion-keeps-name-and-adds-a-version"
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
    """A stack update to an AWS::SSM::Document with UpdateMethod NewVersion keeps the same
    physical document name and adds a version, read back through DescribeDocument versions.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    doc_name = ctx.unique_name("sim2real-behav-ssmdocnv-")
    stack_name = ctx.unique_name("sim2real-behav-ssmdocnv-stack-")
    content_v1 = _content("sim2real-ssmdocnv-v1")
    content_v2 = _content("sim2real-ssmdocnv-v2")

    stack_id, status = _create(ctx, cfn, stack_name, _template(doc_name, content_v1))
    assert status == "CREATE_COMPLETE", (
        f"stack {stack_name} reached {status!r}, expected CREATE_COMPLETE"
    )

    physical_id_before = _doc_physical_id(cfn, stack_id)
    assert physical_id_before == doc_name, (
        f"document physical id after create is {physical_id_before!r}, expected the declared "
        f"Name {doc_name!r}"
    )
    before = ssm.describe_document(Name=doc_name)["Document"]
    assert before["LatestVersion"] == "1", (
        f"a freshly created document's LatestVersion is {before['LatestVersion']!r}, expected '1'"
    )
    assert before["DocumentVersion"] == "1", (
        f"a freshly created document's default DocumentVersion is {before['DocumentVersion']!r}, "
        f"expected '1'"
    )
    assert json.loads(ssm.get_document(Name=doc_name)["Content"]) == content_v1, (
        "the document's content after create does not match the declared Content"
    )

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(doc_name, content_v2))
    status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, stack_id),
        lambda st: st in _UPDATE_TERMINAL,
        timeout_s=300.0,
        interval_s=5.0,
        description=f"stack {stack_name} update",
    )
    assert status == "UPDATE_COMPLETE", f"stack update reached {status!r}, expected UPDATE_COMPLETE"

    physical_id_after = _doc_physical_id(cfn, stack_id)
    assert physical_id_after == doc_name, (
        f"UpdateMethod NewVersion must keep the same physical resource id, but it is now "
        f"{physical_id_after!r}, before was {doc_name!r}"
    )

    after = ssm.describe_document(Name=doc_name)["Document"]
    assert after["LatestVersion"] == "2", (
        f"after the update LatestVersion is {after['LatestVersion']!r}, expected '2'"
    )
    assert after["DocumentVersion"] == "2", (
        f"after the update the default DocumentVersion is {after['DocumentVersion']!r}, expected '2'"
    )

    versions = {
        v["DocumentVersion"]: v
        for v in ssm.list_document_versions(Name=doc_name)["DocumentVersions"]
    }
    assert set(versions) == {"1", "2"}, (
        f"ListDocumentVersions returned versions {sorted(versions)!r}, expected exactly ['1', '2']"
    )
    assert versions["2"]["IsDefaultVersion"] is True, (
        f"version 2 IsDefaultVersion is {versions['2']['IsDefaultVersion']!r}, expected True"
    )
    assert versions["1"]["IsDefaultVersion"] is False, (
        f"version 1 IsDefaultVersion is {versions['1']['IsDefaultVersion']!r}, expected False "
        f"once version 2 became the default"
    )

    content_at_v1 = json.loads(ssm.get_document(Name=doc_name, DocumentVersion="1")["Content"])
    content_at_v2 = json.loads(ssm.get_document(Name=doc_name, DocumentVersion="2")["Content"])
    assert content_at_v1 == content_v1, (
        f"GetDocument DocumentVersion='1' content is {content_at_v1!r}, expected {content_v1!r}"
    )
    assert content_at_v2 == content_v2, (
        f"GetDocument DocumentVersion='2' content is {content_at_v2!r}, expected {content_v2!r}"
    )


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


def _template(doc_name: str, content: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Doc": {
                    "Type": "AWS::SSM::Document",
                    "Properties": {
                        "Name": doc_name,
                        "DocumentType": "Command",
                        "UpdateMethod": "NewVersion",
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
