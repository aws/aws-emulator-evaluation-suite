"""cancel-completed-build-workflow-succeeds-as-a-noop."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cancel-completed-build-workflow-succeeds-as-a-noop"
GROUP = "state-machine"
SERVICES = ["bedrock"]


_SOURCE_DOC = (
    b"All customer refunds over $100 require written manager approval before "
    b"being processed. Employees must never share a customer's personally "
    b"identifiable information with a third party without the customer's "
    b"explicit written consent. Support agents may issue a full refund "
    b"without approval only when the order total is under $25."
)


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CancelAutomatedReasoningPolicyBuildWorkflow on a COMPLETED workflow is a 202 no-op.

    The workflow stays COMPLETED on repeated reads. A positive control first cancels a running
    workflow on the same policy and drives it to CANCELLED, so Cancel demonstrably does something.
    """
    bedrock = ctx.client("bedrock")

    policy_arn = bedrock.create_automated_reasoning_policy(
        name=ctx.unique_name("sim2real-bedrock-arp-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["policyArn"]
    ctx.on_cleanup(lambda: _safe_delete_policy(bedrock, policy_arn))

    # Positive control: cancelling a workflow that is still running succeeds and
    # drives it to CANCELLED. Without this, "cancel on this workflow is a no-op"
    # would be indistinguishable from "cancel never does anything".
    control_workflow_id = _start_ingest_build_workflow(bedrock, policy_arn)
    bedrock.cancel_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=control_workflow_id
    )
    control_status = _wait_for_workflow_status(
        bedrock, policy_arn, control_workflow_id, {"COMPLETED", "FAILED", "CANCELLED"}, timeout_s=600
    )
    assert control_status == "CANCELLED", (
        f"positive control: cancelling a running build workflow should reach "
        f"CANCELLED, got {control_status!r}"
    )

    # A second build workflow on the same policy is left to run to completion.
    workflow_id = _start_ingest_build_workflow(bedrock, policy_arn)

    status = _wait_for_workflow_status(
        bedrock, policy_arn, workflow_id, {"COMPLETED", "FAILED", "CANCELLED"}, timeout_s=1200
    )
    if status != "COMPLETED":
        raise AssertionError(
            f"build workflow reached terminal status {status!r} instead of "
            "COMPLETED; cannot exercise the cancel-after-completion no-op"
        )

    # Cancelling the now-COMPLETED workflow succeeds (202) -- it is a no-op,
    # not a rejection.
    cancel_resp = bedrock.cancel_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id
    )
    cancel_status_code = cancel_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert cancel_status_code == 202, (
        f"expected the idempotent cancel-on-terminal-workflow to be accepted "
        f"(202), got HTTP {cancel_status_code}"
    )

    # Effect absent, checked on three independent reads a beat apart: the
    # workflow does not drift away from COMPLETED as a delayed side effect of
    # the accepted-but-inapplicable cancel.
    for _ in range(3):
        final = bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )
        assert final["status"] == "COMPLETED", (
            f"cancelling an already-COMPLETED workflow should be a no-op, but "
            f"status became {final['status']!r}"
        )
        time.sleep(5)


def _start_ingest_build_workflow(bedrock, policy_arn: str) -> str:
    resp = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="INGEST_CONTENT",
        sourceContent={
            "workflowContent": {
                "documents": [
                    {
                        "document": _SOURCE_DOC,
                        "documentContentType": "txt",
                        "documentName": "refund-policy.txt",
                    }
                ]
            }
        },
    )
    return resp["buildWorkflowId"]


def _safe_delete_policy(bedrock, policy_arn: str) -> None:
    """Delete the policy with its build workflows; an already-deleted policy needs nothing."""
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_automated_reasoning_policy(policyArn=policy_arn, force=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_workflow_status(bedrock, policy_arn: str, workflow_id: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = ""
    while time.monotonic() < deadline:
        status = bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )["status"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"build workflow never reached a terminal status, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
