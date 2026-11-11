"""deploy-ssm-document-via-cloudformation-then-send-command."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-ssm-document-via-cloudformation-then-send-command"
GROUP = "deploy"
SERVICES = ["ssm"]


def _doc_content() -> dict:
    return {
        "schemaVersion": "2.2",
        "description": "sim2real deploy-then-send-command test document",
        "mainSteps": [
            {
                "action": "aws:runShellScript",
                "name": "runShell",
                "inputs": {"runCommand": ["echo hello-sim2real"]},
            }
        ],
    }


def _template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"DocName": {"Type": "String"}},
        "Resources": {
            "Doc": {
                "Type": "AWS::SSM::Document",
                "Properties": {
                    "Name": {"Ref": "DocName"},
                    "DocumentType": "Command",
                    "Content": _doc_content(),
                },
            }
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::SSM::Document is referenceable by SendCommand and its content
    is retrievable unchanged via GetDocument. Deleting the stack removes the document."""
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack_name = ctx.unique_name("sim2real-ssmdoc-stack-")
    doc_name = ctx.unique_name("sim2real-ssmdoc-")

    def _error(fn):
        """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an
        emulator that accepts what AWS refuses cannot read as a code mismatch."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message", "")
        raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template()),
        Parameters=[{"ParameterKey": "DocName", "ParameterValue": doc_name}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    got = ssm.get_document(Name=doc_name, DocumentFormat="JSON")
    content = json.loads(got["Content"])
    assert content["mainSteps"][0]["inputs"]["runCommand"] == ["echo hello-sim2real"]
    assert content["description"] == "sim2real deploy-then-send-command test document"

    # There is no real managed instance in this account, so SendCommand cannot fully
    # succeed. The behavior under test is that the CFN-deployed document itself is
    # valid and referenceable by SendCommand: validation proceeds past document lookup
    # and fails specifically on the (fabricated) instance, not on the document.
    #
    # Control: without a document-specific error to contrast against, InvalidInstanceId
    # would be uninformative -- it could mean "the document passed validation" or
    # equally "SendCommand never got far enough to look at the document at all". Probe
    # with a document name that cannot exist, same fabricated instance, and require a
    # different, document-specific error.
    missing_doc_code, missing_doc_message = _error(
        lambda: ssm.send_command(
            DocumentName=ctx.unique_name("sim2real-ssmdoc-missing-"),
            InstanceIds=["i-0123456789abcdef0"],
        )
    )
    assert missing_doc_code == "InvalidDocument", (
        f"expected a document-specific rejection for a nonexistent DocumentName, "
        f"got {missing_doc_code!r} -- InvalidInstanceId here would make the real "
        f"assertion below meaningless"
    )
    # AWS sends this InvalidDocument with an empty message.
    assert missing_doc_message == "", missing_doc_message

    real_doc_code, real_doc_message = _error(
        lambda: ssm.send_command(DocumentName=doc_name, InstanceIds=["i-0123456789abcdef0"])
    )
    assert real_doc_code == "InvalidInstanceId", (
        f"expected the CFN-deployed document to pass validation and SendCommand to "
        f"fail only on the fabricated instance, got {real_doc_code!r}"
    )
    assert real_doc_message == "Instances not in a valid state for account", real_doc_message

    # Teardown proves symmetric: deleting the stack must remove the document CFN
    # created, not just the stack's own bookkeeping record.
    _delete_stack(cfn, stack_name)
    post_delete_code, post_delete_message = _error(lambda: ssm.get_document(Name=doc_name))
    assert post_delete_code == "InvalidDocument", (
        f"expected the document to be gone after stack delete, got {post_delete_code!r}"
    )
    assert post_delete_message == f"Document with name {doc_name} does not exist.", (
        post_delete_message
    )


# ===== helpers =====
def _delete_stack(cfn, stack_name: str) -> None:
    # DeleteStack on a deleted stack is a no-op and the waiter counts "does not exist" as done.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
