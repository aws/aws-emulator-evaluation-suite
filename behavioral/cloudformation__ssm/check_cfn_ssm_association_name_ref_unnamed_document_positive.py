"""cfn-ssm-association-name-ref-unnamed-document-positive."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-association-name-ref-unnamed-document-positive"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]


_CONTENT = {
    "schemaVersion": "2.2",
    "description": "sim2real unnamed document test",
    "mainSteps": [
        {
            "action": "aws:runShellScript",
            "name": "runShellScript",
            "inputs": {"runCommand": ["echo hello-from-unnamed-doc"]},
        }
    ],
}


def _template(tag_key: str, tag_value: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Doc": {
                "Type": "AWS::SSM::Document",
                "Properties": {
                    "DocumentType": "Command",
                    "Content": _CONTENT,
                },
            },
            "Assoc": {
                "Type": "AWS::SSM::Association",
                "Properties": {
                    "Name": {"Ref": "Doc"},
                    "Targets": [{"Key": f"tag:{tag_key}", "Values": [tag_value]}],
                },
            },
        },
        "Outputs": {
            "DocumentName": {"Value": {"Ref": "Doc"}},
            "AssociationId": {"Value": {"Fn::GetAtt": ["Assoc", "AssociationId"]}},
        },
    }


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An unnamed AWS::SSM::Document and an AWS::SSM::Association naming it by Ref reach
    CREATE_COMPLETE; Ref is "<stack>-Doc-<12 alphanumerics>", GetDocument returns the template's
    content, and the association's Overview settles at Status and DetailedStatus Success."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    tag_key = "Sim2realAssocTarget"
    tag_value = ctx.unique_name("assoc-target-")
    stack_name = ctx.unique_name("sim2real-ssmdoc-ref-stack-")
    template = json.dumps(_template(tag_key, tag_value))

    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=template)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))
    status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, stack_id),
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
                "DELETE_COMPLETE",
                "DELETE_FAILED",
            }
        ),
        timeout_s=180.0,
        interval_s=5.0,
        description=f"stack {stack_name} creation",
    )
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    doc_name = outputs["DocumentName"]
    association_id = outputs["AssociationId"]
    # CloudFormation names an unnamed document "<stack name>-<logical id>-<12 alphanumerics>".
    assert re.fullmatch(re.escape(f"{stack_name}-Doc-") + r"[A-Za-z0-9]{12}", doc_name), (
        f"expected the generated name {stack_name}-Doc-<12 alphanumerics>, got {doc_name!r}"
    )

    # CloudFormation's own resource read confirms the physical ID that Ref resolved to: an
    # independent read of the same relationship, through a different operation.
    doc_resource = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Doc")[
        "StackResourceDetail"
    ]
    assert doc_resource["PhysicalResourceId"] == doc_name, (
        f"Ref produced {doc_name!r} but CloudFormation's own resource record names the "
        f"physical ID {doc_resource['PhysicalResourceId']!r}"
    )

    got = ssm.get_document(Name=doc_name)
    assert got["Status"] == "Active", f"expected GetDocument Status Active, got {got['Status']!r}"
    assert got["DocumentType"] == "Command", (
        f"expected GetDocument DocumentType Command, got {got['DocumentType']!r}"
    )
    assert json.loads(got["Content"]) == _CONTENT, (
        f"expected GetDocument Content to be the template's content, got {got['Content']!r}"
    )

    described = ssm.describe_association(AssociationId=association_id)["AssociationDescription"]
    assert described["Name"] == doc_name, (
        f"expected DescribeAssociation Name {doc_name!r}, got {described['Name']!r}"
    )

    # The tag no managed node carries resolves zero targets; Overview settles at Success.
    overview = _poll_until(
        ctx,
        lambda: ssm.describe_association(AssociationId=association_id)[
            "AssociationDescription"
        ].get("Overview", {}),
        lambda o: o.get("Status") in {"Success", "Failed"},
        timeout_s=300.0,
        interval_s=5.0,
        description=f"association {association_id} Overview.Status to settle",
    )
    assert overview.get("Status") == "Success", (
        f"expected the association to settle at Overview.Status Success, got {overview!r}"
    )
    assert overview.get("DetailedStatus") == "Success", (
        f"expected Overview.DetailedStatus Success, got {overview!r}"
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
        lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED"},
        timeout_s=300.0,
        interval_s=5.0,
        description=f"delete stack {stack_id}",
    )
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {status!r}, not DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
