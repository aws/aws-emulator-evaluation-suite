"""start-test-workflow-while-in-use-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-test-workflow-while-in-use-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second StartAutomatedReasoningPolicyTestWorkflow for a buildWorkflowId whose test workflow is
    still running returns ResourceInUseException 'Testing workflow is currently in progress' without
    disturbing that run, and a new run starts and finishes once the first is terminal."""
    bedrock = ctx.client("bedrock")

    policy = bedrock.create_automated_reasoning_policy(
        name=ctx.unique_name("sim2real-arp-"),
        tags=[{"key": "sim2real", "value": "start-test-workflow-while-in-use-rejected"}],
    )
    policy_arn = policy["policyArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)))

    document_text = (
        b"Refund policy: Customers may request a full refund within 30 days of purchase. "
        b"After 30 days, no refunds are issued. Employees must approve any refund over $500."
    )
    build = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="INGEST_CONTENT",
        sourceContent={
            "workflowContent": {
                "documents": [
                    {
                        "document": document_text,
                        "documentContentType": "txt",
                        "documentName": "refund-policy",
                    }
                ]
            }
        },
    )
    build_workflow_id = build["buildWorkflowId"]
    _wait_for_build_status(ctx, policy_arn, build_workflow_id, {"COMPLETED"})

    # A real test case gives the test workflow genuine work to do, so the "still running" window
    # this check races against is real asynchrony rather than a call that completes trivially fast
    # because there was nothing to test.
    test_case = bedrock.create_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        guardContent=(
            "A customer was given a full refund 45 days after purchase, with no employee "
            "approval on file, even though the refund exceeded $500."
        ),
        expectedAggregatedFindingsResult="INVALID",
        confidenceThreshold=0.5,
    )
    test_case_id = test_case["testCaseId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: _delete_test_case(bedrock, policy_arn, test_case_id)))

    # First test workflow: this call succeeding is the in-file positive control for the
    # mechanism working under normal (not-already-in-use) conditions.
    bedrock.start_automated_reasoning_policy_test_workflow(
        policyArn=policy_arn, buildWorkflowId=build_workflow_id, testCaseIds=[test_case_id]
    )

    # Immediately race a second start against the same build workflow while the first is still
    # active -- this must be rejected.
    code, message = _error(
        lambda: bedrock.start_automated_reasoning_policy_test_workflow(
            policyArn=policy_arn, buildWorkflowId=build_workflow_id, testCaseIds=[test_case_id]
        )
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}: {message!r}"
    assert message == "Testing workflow is currently in progress", f"unexpected rejection message: {message!r}"

    # Effect absent, via an independent read at a different operation than the one that mutated:
    # the rejected concurrent start did not reset the first run. The result record can lag the
    # in-use lock by a beat, so this is a bounded retry (never a bare instantaneous read) waiting
    # for it to leave NOT_STARTED -- and it must do so without ever snapping back to it.
    _wait_for_test_result(
        ctx,
        policy_arn,
        build_workflow_id,
        test_case_id,
        {"SCHEDULED", "IN_PROGRESS", "COMPLETED", "FAILED"},
        timeout_s=60.0,
    )

    # Let the first test workflow settle to a terminal state before reusing the build workflow.
    _wait_for_test_result(ctx, policy_arn, build_workflow_id, test_case_id, {"COMPLETED", "FAILED"})

    # Once the prior test workflow is terminal, starting a new one succeeds again --
    # proving the earlier rejection was specifically about the concurrent test run, not a
    # permanent lock on the build workflow.
    bedrock.start_automated_reasoning_policy_test_workflow(
        policyArn=policy_arn, buildWorkflowId=build_workflow_id, testCaseIds=[test_case_id]
    )

    # Independent terminal read, at a different operation than the one that just mutated: the
    # restored call really did start a new run that itself reaches a terminal state, rather than
    # succeeding while quietly doing nothing.
    final_result = _wait_for_test_result(
        ctx, policy_arn, build_workflow_id, test_case_id, {"COMPLETED", "FAILED"}
    )
    assert final_result["testCase"]["testCaseId"] == test_case_id, (
        f"expected the restarted run's result to be for test case {test_case_id!r}, "
        f"got {final_result['testCase']['testCaseId']!r}"
    )
    assert final_result["policyArn"] == policy_arn, (
        f"expected the restarted run's result to be for policy {policy_arn!r}, "
        f"got {final_result['policyArn']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_build_status(ctx, policy_arn: str, build_workflow_id: str, terminal_statuses, timeout_s: float = 60 * 20):
    bedrock = ctx.client("bedrock")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=build_workflow_id
        )
        last_status = resp["status"]
        if last_status in terminal_statuses:
            return resp
        time.sleep(2)
    raise AssertionError(
        f"build workflow never reached {terminal_statuses} within {timeout_s}s, last saw {last_status!r}"
    )


def _wait_for_test_result(
    ctx,
    policy_arn: str,
    build_workflow_id: str,
    test_case_id: str,
    terminal_statuses,
    timeout_s: float = 60 * 15,
):
    from botocore.exceptions import ClientError

    bedrock = ctx.client("bedrock")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            result = bedrock.get_automated_reasoning_policy_test_result(
                policyArn=policy_arn, buildWorkflowId=build_workflow_id, testCaseId=test_case_id
            )["testResult"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_status = "NOT_STARTED"
            time.sleep(5.0)
            continue
        last_status = result["testRunStatus"]
        if last_status in terminal_statuses:
            return result
        time.sleep(2)
    raise AssertionError(
        f"test result for test case {test_case_id!r} never reached {terminal_statuses} within "
        f"{timeout_s}s, last saw {last_status!r}"
    )


def _delete_test_case(bedrock, policy_arn: str, test_case_id: str) -> None:
    current = bedrock.get_automated_reasoning_policy_test_case(
        policyArn=policy_arn, testCaseId=test_case_id
    )["testCase"]
    bedrock.delete_automated_reasoning_policy_test_case(
        policyArn=policy_arn, testCaseId=test_case_id, lastUpdatedAt=current["updatedAt"]
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
