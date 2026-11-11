"""automated-reasoning-build-workflow-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automated-reasoning-build-workflow-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartAutomatedReasoningPolicyBuildWorkflow transitions InProgress->Completed
    and DeleteAutomatedReasoningPolicyBuildWorkflow removes the workflow."""
    bedrock = ctx.client("bedrock")
    policy_arn = _create_policy(ctx, bedrock)
    definition = _minimal_policy_definition()

    started = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="GENERATE_POLICY_SCENARIOS",
        sourceContent={"policyDefinition": definition},
    )
    workflow_id = started["buildWorkflowId"]

    def _probe():
        return bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )

    final = _poll_until(
        _probe,
        lambda r: r["status"] in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=900.0,
        interval_s=10.0,
    )
    assert final["status"] == "COMPLETED", f"build workflow ended in {final['status']!r}"

    bedrock.delete_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id, lastUpdatedAt=final["updatedAt"]
    )

    code, message = _error(
        lambda: bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        ),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after deleting build workflow {workflow_id!r}, got {code!r}"
    )
    assert message == "Build WorkflowExecution not found", (
        f"unexpected not-found message after deleting build workflow {workflow_id!r}: {message!r}"
    )


def _error(fn, *, timeout_s=0.0, interval_s=2.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    succeeds once timeout_s has passed raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError("expected the call to be refused, but it succeeded")
        time.sleep(interval_s)


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _minimal_policy_definition() -> dict:
    return {
        "version": "1",
        "types": [],
        "variables": [
            {
                "name": "isFullTime",
                "type": "BOOL",
                "description": (
                    "Whether the employee works full-time. Set to true when the text "
                    "describes the employee as full-time or working full hours."
                ),
            },
            {
                "name": "eligibleForBenefits",
                "type": "BOOL",
                "description": "Whether the employee is eligible for company benefits.",
            },
        ],
        "rules": [
            {"id": "RULE00000001", "expression": "(=> isFullTime eligibleForBenefits)"}
        ],
    }


def _create_policy(ctx, bedrock) -> str:
    name = ctx.unique_name("sim2real-arp-")
    resp = bedrock.create_automated_reasoning_policy(
        name=name, policyDefinition=_minimal_policy_definition(),
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    policy_arn = resp["policyArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))
    )
    return policy_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
