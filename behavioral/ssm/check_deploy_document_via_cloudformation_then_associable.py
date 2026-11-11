"""deploy-document-via-cloudformation-then-associable."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-document-via-cloudformation-then-associable"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SSM::Document is Active as a Command document in GetDocument and
    DescribeDocument, and CreateAssociation on it starts Pending and settles at Success with no matching
    instance."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-cfn-doc-")
    content = {
        "schemaVersion": "2.2",
        "description": "sim2real behavioral test document",
        "mainSteps": [
            {
                "action": "aws:runShellScript",
                "name": "runShellScript",
                "inputs": {"runCommand": ["echo hello-from-sim2real"]},
            }
        ],
    }
    template = json.dumps(
        {
            "Resources": {
                "Doc": {
                    "Type": "AWS::SSM::Document",
                    "Properties": {
                        "Name": doc_name,
                        "DocumentType": "Command",
                        "Content": content,
                    },
                }
            }
        }
    )
    _deploy_cfn_stack(ctx, template)

    doc = ssm.get_document(Name=doc_name)
    assert doc["Status"] == "Active", f"expected Active, got {doc['Status']}"
    assert doc["DocumentType"] == "Command", (
        f"expected DocumentType Command, got {doc['DocumentType']}"
    )

    described = ssm.describe_document(Name=doc_name)["Document"]
    assert described["Status"] == "Active", (
        f"expected DescribeDocument Status Active, got {described['Status']}"
    )

    # A run-unique tag no managed node carries: the association targets no instance.
    no_node = [{"Key": "tag:sim2real-target", "Values": [ctx.unique_name("sim2real-no-node-")]}]
    assoc = ssm.create_association(Name=doc_name, Targets=no_node)["AssociationDescription"]
    association_id = assoc["AssociationId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ssm.delete_association(AssociationId=association_id))
    )
    assert assoc["Name"] == doc_name, f"expected Name {doc_name}, got {assoc['Name']}"
    overview_status = assoc.get("Overview", {}).get("Status")
    assert overview_status == "Pending", (
        f"expected a freshly created association to start Pending, got {overview_status!r}"
    )

    # Overview settles asynchronously; with no matching managed instances it reaches Success.
    overview = _poll_until(
        lambda: ssm.describe_association(AssociationId=association_id)[
            "AssociationDescription"
        ].get("Overview", {}),
        lambda o: o.get("Status") in ("Success", "Failed"),
        timeout_s=300,
        interval_s=5,
        what=f"association {association_id} Overview.Status to settle",
    )
    assert overview.get("Status") == "Success", (
        f"expected the association to settle at Overview.Status Success, got {overview}"
    )
    assert overview.get("DetailedStatus") == "Success", (
        f"expected Overview.DetailedStatus Success, got {overview}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, what="condition"):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last value {value!r}")


def _deploy_cfn_stack(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ssm-cfn-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    return {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
