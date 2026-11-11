"""e2e-automated-reasoning-policy-build-and-test-workflow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-automated-reasoning-policy-build-and-test-workflow"
GROUP = "e2e"
SERVICES = ["bedrock"]

_TERMINAL_BUILD_STATUSES = {"COMPLETED", "FAILED", "CANCELLED"}
_TERMINAL_TEST_STATUSES = {"COMPLETED", "FAILED"}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not reach the expected state within {timeout_s}s; last={last!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A build workflow on a new policy completes, feeds a version, and a test workflow runs against it."""
    bedrock = ctx.client("bedrock")

    policy_name = ctx.unique_name("sim2real-arc-e2e-")
    policy = bedrock.create_automated_reasoning_policy(
        name=policy_name,
        tags=[{"key": "sim2real", "value": "e2e-automated-reasoning-policy-build-and-test-workflow"}],
    )
    policy_arn = policy["policyArn"]
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))

    source_document = (
        b"Expense Reimbursement Policy\n\n"
        b"All expense reimbursements over $100 require written approval from a manager before "
        b"payment is processed. Reimbursements of $100 or less may be approved by the employee's "
        b"direct supervisor via email. No reimbursement may be processed without at least one "
        b"documented approval."
    )

    build = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="INGEST_CONTENT",
        sourceContent={
            "workflowContent": {
                "documents": [
                    {
                        "document": source_document,
                        "documentContentType": "txt",
                        "documentName": "expense-policy.txt",
                        "documentDescription": "Expense reimbursement approval policy",
                    }
                ]
            }
        },
    )
    build_workflow_id = build["buildWorkflowId"]

    build_status = _poll_until(
        lambda: bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=build_workflow_id
        ),
        lambda resp: resp["status"] in _TERMINAL_BUILD_STATUSES,
        timeout_s=1800.0,
        interval_s=20.0,
        description=f"build workflow {build_workflow_id}",
    )
    assert build_status["status"] == "COMPLETED", (
        f"expected the ingest-content build workflow to COMPLETE, got {build_status['status']!r}"
    )

    policy_after_build = bedrock.get_automated_reasoning_policy(policyArn=policy_arn)
    definition_hash = policy_after_build["definitionHash"]

    version_resp = bedrock.create_automated_reasoning_policy_version(
        policyArn=policy_arn, lastUpdatedDefinitionHash=definition_hash
    )
    expected_arn_prefix = policy_arn.split(":automated-reasoning-policy/")[0]
    assert version_resp["policyArn"].startswith(expected_arn_prefix), (
        f"expected the new version's policyArn to start with {expected_arn_prefix!r}, "
        f"got {version_resp['policyArn']!r}"
    )
    assert version_resp["version"].isdigit() and int(version_resp["version"]) >= 1, (
        f"expected a positive integer version string, got {version_resp['version']!r}"
    )

    test_case = bedrock.create_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        guardContent=(
            "An expense of $250 was reimbursed after only the employee's direct supervisor "
            "approved it by email, with no additional written manager approval."
        ),
        expectedAggregatedFindingsResult="INVALID",
        confidenceThreshold=0.5,
    )
    test_case_id = test_case["testCaseId"]

    def _delete_test_case() -> None:
        current = bedrock.get_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id
        )["testCase"]
        bedrock.delete_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id, lastUpdatedAt=current["updatedAt"]
        )

    ctx.on_cleanup(_delete_test_case)

    bedrock.start_automated_reasoning_policy_test_workflow(
        policyArn=policy_arn, buildWorkflowId=build_workflow_id, testCaseIds=[test_case_id]
    )

    def _probe_test_result():
        try:
            return bedrock.get_automated_reasoning_policy_test_result(
                policyArn=policy_arn, buildWorkflowId=build_workflow_id, testCaseId=test_case_id
            )["testResult"]
        except bedrock.exceptions.ResourceNotFoundException:
            return {"testRunStatus": "NOT_STARTED"}

    test_result = _poll_until(
        _probe_test_result,
        lambda resp: resp["testRunStatus"] in _TERMINAL_TEST_STATUSES,
        timeout_s=900.0,
        interval_s=15.0,
        description=f"test workflow for test case {test_case_id}",
    )

    assert test_result["testRunStatus"] == "COMPLETED", (
        f"expected the test workflow run to COMPLETE, got {test_result['testRunStatus']!r}"
    )
    assert test_result["testCase"]["testCaseId"] == test_case_id, (
        f"expected the result's test case id to be {test_case_id!r}, got "
        f"{test_result['testCase']['testCaseId']!r}"
    )
    assert test_result["policyArn"] == policy_arn, (
        f"expected the result's policyArn to be {policy_arn!r}, got {test_result['policyArn']!r}"
    )
    expected_finding = test_result["testCase"]["expectedAggregatedFindingsResult"]
    assert expected_finding == "INVALID", (
        f"expected the echoed test case to keep declaring INVALID, got {expected_finding!r}"
    )
    aggregated_finding = test_result.get("aggregatedTestFindingsResult")
    run_result = test_result.get("testRunResult")
    matched_expectation = aggregated_finding == expected_finding
    assert (run_result == "PASSED") == matched_expectation, (
        "the test run's own PASSED/FAILED verdict should agree with whether the aggregated finding "
        f"({aggregated_finding!r}) matches the test case's declared expectation ({expected_finding!r}); "
        f"got testRunResult={run_result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
