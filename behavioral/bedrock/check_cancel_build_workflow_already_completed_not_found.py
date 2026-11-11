"""cancel-build-workflow-already-completed-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-build-workflow-already-completed-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelAutomatedReasoningPolicyBuildWorkflow on a workflow already cancelled and
    deleted returns ResourceNotFoundException, while a second in-flight workflow on the
    same policy can still be cancelled."""
    bedrock = ctx.client("bedrock")
    policy_arn = _create_ar_policy(ctx)

    workflow_id = _start_ingest_build_workflow(ctx, policy_arn, "policy source A")
    ctx.on_cleanup(lambda: _delete_workflow(bedrock, policy_arn, workflow_id))
    bedrock.cancel_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id
    )
    status = _poll_until_terminal(bedrock, policy_arn, workflow_id)
    assert status == "CANCELLED", f"expected the workflow to reach CANCELLED, last status={status}"

    wf = bedrock.get_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id
    )
    bedrock.delete_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id, lastUpdatedAt=wf["updatedAt"]
    )

    # negative: the workflow record has now been deleted -- cancelling it again
    # is a not-found, not a silent no-op or a state-conflict
    code, message = _error(
        lambda: bedrock.cancel_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Build WorkflowExecution not found", (
        f"expected message 'Build WorkflowExecution not found', got {message!r}"
    )

    # effect absent: the deleted workflow record was not resurrected by the failed
    # cancel attempt
    get_code, get_message = _error(
        lambda: bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )
    )
    assert get_code == "ResourceNotFoundException", f"expected the deleted workflow to stay gone, got {get_code}"
    assert get_message == "Build WorkflowExecution not found", (
        f"expected message 'Build WorkflowExecution not found', got {get_message!r}"
    )

    # positive control: a fresh build workflow on the same policy can still be
    # cancelled successfully -- only the deleted id is rejected, not the whole
    # Cancel operation.
    workflow_id_2 = _start_ingest_build_workflow(ctx, policy_arn, "policy source B")
    ctx.on_cleanup(lambda: _delete_workflow(bedrock, policy_arn, workflow_id_2))
    bedrock.cancel_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id_2
    )
    status2 = _poll_until_terminal(bedrock, policy_arn, workflow_id_2)
    assert status2 == "CANCELLED", f"expected the second workflow to reach CANCELLED, last status={status2}"


def _create_ar_policy(ctx) -> str:
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-bedrock-arpwf-")
    created = bedrock.create_automated_reasoning_policy(
        name=name,
        tags=[{"key": "sim2real", "value": "cancel-build-workflow-already-completed-not-found"}],
    )
    policy_arn = created["policyArn"]
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))
    return policy_arn


def _start_ingest_build_workflow(ctx, policy_arn: str, text: str) -> str:
    bedrock = ctx.client("bedrock")
    resp = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="INGEST_CONTENT",
        sourceContent={
            "workflowContent": {
                "documents": [
                    {
                        "document": text.encode("utf-8"),
                        "documentContentType": "txt",
                        "documentName": "policy-source.txt",
                    }
                ]
            }
        },
    )
    return resp["buildWorkflowId"]


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


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
