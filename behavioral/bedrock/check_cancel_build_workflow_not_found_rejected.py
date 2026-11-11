"""cancel-build-workflow-not-found-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-build-workflow-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelAutomatedReasoningPolicyBuildWorkflow on an unknown workflow id returns
    ResourceNotFoundException, while a real in-flight workflow on the same policy is
    cancelled, so the rejection is specific to the unknown id."""
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-arp-")
    created = bedrock.create_automated_reasoning_policy(
        name=name, policyDefinition={}, tags=[{"key": "sim2real", "value": CHECK}]
    )
    policy_arn = created["policyArn"]
    ctx.on_cleanup(lambda: _safe_delete_policy(bedrock, policy_arn))

    # positive control: a real, in-flight build workflow on this policy is genuinely
    # cancellable.
    real_workflow_id = _start_ingest_build_workflow(bedrock, policy_arn)
    ctx.on_cleanup(lambda: _delete_workflow(bedrock, policy_arn, real_workflow_id))
    bedrock.cancel_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=real_workflow_id
    )
    status = _poll_until_terminal(bedrock, policy_arn, real_workflow_id)
    assert status == "CANCELLED", (
        f"expected the real build workflow to reach CANCELLED, last status={status!r}"
    )

    before = _workflow_ids(bedrock, policy_arn)

    bogus_workflow_id = str(uuid.uuid4())
    code, message = _error(
        lambda: bedrock.cancel_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=bogus_workflow_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Build WorkflowExecution not found", (
        f"expected message 'Build WorkflowExecution not found', got {message!r}"
    )

    # effect absent: the rejected call created or altered nothing -- the build
    # workflow set at this policy is exactly what it was beforehand.
    after = _workflow_ids(bedrock, policy_arn)
    assert after == before, (
        f"expected the build workflow set to be unchanged by the rejected call, "
        f"before={before!r} after={after!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected success raises,
    because accepting input AWS refuses must fail as such, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _workflow_ids(bedrock, policy_arn: str) -> list[str]:
    listing = bedrock.list_automated_reasoning_policy_build_workflows(policyArn=policy_arn)
    return sorted(
        w["buildWorkflowId"]
        for w in listing.get("automatedReasoningPolicyBuildWorkflowSummaries", [])
    )


def _start_ingest_build_workflow(bedrock, policy_arn: str) -> str:
    resp = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="INGEST_CONTENT",
        sourceContent={
            "workflowContent": {
                "documents": [
                    {
                        "document": b"Refunds over $100 require manager approval.",
                        "documentContentType": "txt",
                        "documentName": "policy-source.txt",
                    }
                ]
            }
        },
    )
    return resp["buildWorkflowId"]


def _poll_until_terminal(
    bedrock, policy_arn: str, workflow_id: str, timeout_s: float = 180.0, interval_s: float = 5.0
) -> str:
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
    raise AssertionError(f"workflow {workflow_id} never reached a terminal state, last status={last!r}")


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


def _safe_delete_policy(bedrock, policy_arn: str) -> None:
    try:
        bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
