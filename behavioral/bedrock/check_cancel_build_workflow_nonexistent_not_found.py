"""cancel-build-workflow-nonexistent-not-found."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "cancel-build-workflow-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelAutomatedReasoningPolicyBuildWorkflow on a never-issued workflow id returns
    ResourceNotFoundException, while Cancel on a real in-progress workflow of the same policy
    succeeds and reaches CANCELLED."""
    bedrock = ctx.client("bedrock")

    created = bedrock.create_automated_reasoning_policy(
        name=ctx.unique_name("sim2real-arp-"),
        tags=[{"key": "sim2real", "value": "true"}],
    )
    policy_arn = created["policyArn"]
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))

    # Positive control: without it the ResourceNotFoundException below could not be told
    # apart from Cancel rejecting every buildWorkflowId.
    started = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="INGEST_CONTENT",
        sourceContent={
            "workflowContent": {
                "documents": [
                    {
                        "document": b"Refunds over $100 require written manager approval.",
                        "documentContentType": "txt",
                        "documentName": "policy-source.txt",
                    }
                ]
            }
        },
    )
    real_workflow_id = started["buildWorkflowId"]
    ctx.on_cleanup(lambda: _delete_workflow(bedrock, policy_arn, real_workflow_id))
    bedrock.cancel_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=real_workflow_id
    )
    real_status = _poll_until_terminal(bedrock, policy_arn, real_workflow_id)
    assert real_status == "CANCELLED", (
        f"expected the real, freshly-started workflow to reach CANCELLED, last status={real_status}"
    )

    # Syntactically valid, but never issued for this policy.
    bogus_workflow_id = str(uuid.uuid4())

    code, message = _error(
        lambda: bedrock.cancel_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=bogus_workflow_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Build WorkflowExecution not found", (
        f"expected message 'Build WorkflowExecution not found', got {message!r}"
    )

    got = bedrock.get_automated_reasoning_policy(policyArn=policy_arn)
    assert got["policyArn"] == policy_arn, f"expected policy {policy_arn} to still be describable, got {got.get('policyArn')}"

    # The bogus cancel neither created nor touched any workflow.
    listed = bedrock.list_automated_reasoning_policy_build_workflows(policyArn=policy_arn)
    ids = [w["buildWorkflowId"] for w in listed["automatedReasoningPolicyBuildWorkflowSummaries"]]
    assert ids == [real_workflow_id], f"expected only {real_workflow_id}, got {ids}"


def _error(fn):
    """(Error.Code, Error.Message) of the refused call; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_terminal(bedrock, policy_arn: str, workflow_id: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    terminal = {"COMPLETED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        wf = bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )
        last = wf["status"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"workflow {workflow_id} never reached a terminal state, last status={last}")


def _delete_workflow(bedrock, policy_arn: str, workflow_id: str) -> None:
    """Cancel, wait out and delete one build workflow: a policy holding any is undeletable."""
    from botocore.exceptions import ClientError

    try:
        wf = bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )
        if wf["status"] not in ("COMPLETED", "FAILED", "CANCELLED"):
            bedrock.cancel_automated_reasoning_policy_build_workflow(
                policyArn=policy_arn, buildWorkflowId=workflow_id
            )
        _poll_until_terminal(bedrock, policy_arn, workflow_id)
        wf = bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    bedrock.delete_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id, lastUpdatedAt=wf["updatedAt"]
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
