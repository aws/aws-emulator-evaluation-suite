"""start-test-workflow-resource-in-use-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-test-workflow-resource-in-use-blocked"
GROUP = "error-semantics"
SERVICES = ["bedrock"]

_IN_FLIGHT_STATUSES = {"SCHEDULED", "PREPROCESSING", "BUILDING", "TESTING"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Starting a test workflow on an in-flight build returns ValidationException naming the build.

    Other policy APIs stay usable, and the same call succeeds once that build reaches COMPLETED.
    """
    bedrock = ctx.client("bedrock")
    policy_arn = _create_ar_policy(ctx)

    first_build_id = _start_ingest_build_workflow(
        bedrock,
        policy_arn,
        "Refunds are only permitted within 30 days of purchase. All refund "
        "requests over $500 must be approved by a manager before being issued.",
        "policy-source.txt",
    )
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.cancel_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=first_build_id
    )))
    first_status = _poll_until(
        lambda: bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=first_build_id
        )["status"],
        lambda s: s in ("COMPLETED", "FAILED"),
        timeout_s=1800.0,
        interval_s=15.0,
        description="first build workflow reaching a terminal state",
    )
    assert first_status == "COMPLETED", (
        f"expected the setup build workflow to COMPLETE, got {first_status!r}"
    )

    # The test workflow needs an existing version and test case, or it is ResourceNotFound.
    definition_hash = bedrock.get_automated_reasoning_policy(policyArn=policy_arn)["definitionHash"]
    bedrock.create_automated_reasoning_policy_version(
        policyArn=policy_arn, lastUpdatedDefinitionHash=definition_hash
    )
    test_case_id = bedrock.create_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        guardContent=(
            "A refund of $600 was issued 45 days after purchase with no manager approval."
        ),
        expectedAggregatedFindingsResult="INVALID",
        confidenceThreshold=0.5,
    )["testCaseId"]

    def _delete_test_case() -> None:
        current = bedrock.get_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id
        )["testCase"]
        bedrock.delete_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id, lastUpdatedAt=current["updatedAt"]
        )

    ctx.on_cleanup(lambda: _safe(_delete_test_case))

    # A second build provides an in-flight build to conflict with.
    second_build_id = _start_ingest_build_workflow(
        bedrock,
        policy_arn,
        "Store credit issued in place of a refund does not expire and may be "
        "combined with future purchases without manager approval.",
        "policy-amendment.txt",
    )
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.cancel_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=second_build_id
    )))

    # The new build is not readable immediately after Start returns.
    status = _poll_until(
        lambda: bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=second_build_id
        )["status"],
        lambda s: s in _IN_FLIGHT_STATUSES | {"COMPLETED", "FAILED"},
        timeout_s=60.0,
        interval_s=3.0,
        description="second build workflow becoming visible",
    )
    assert status in _IN_FLIGHT_STATUSES, (
        f"expected the second build workflow to still be in flight when probed, status={status!r}"
    )

    code, message = _error_detail(
        lambda: bedrock.start_automated_reasoning_policy_test_workflow(
            policyArn=policy_arn, buildWorkflowId=second_build_id, testCaseIds=[test_case_id]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code} ({message})"
    assert message == f"Build workflow: {second_build_id} is not in COMPLETED status", (
        f"expected a not-in-COMPLETED-status message naming {second_build_id!r}, got {message!r}"
    )

    wf = bedrock.get_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=second_build_id
    )
    assert wf["status"] in _IN_FLIGHT_STATUSES, (
        f"expected the second build workflow to still be in flight, status={wf['status']!r}"
    )

    listed = bedrock.list_automated_reasoning_policy_build_workflows(policyArn=policy_arn)
    ids = {s["buildWorkflowId"] for s in listed["automatedReasoningPolicyBuildWorkflowSummaries"]}
    assert {first_build_id, second_build_id} <= ids, (
        f"expected {first_build_id!r} and {second_build_id!r} among listed build workflows, got {ids!r}"
    )

    final_status = _poll_until(
        lambda: bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=second_build_id
        )["status"],
        lambda s: s in ("COMPLETED", "FAILED"),
        timeout_s=1800.0,
        interval_s=15.0,
        description="second build workflow reaching a terminal state",
    )
    assert final_status == "COMPLETED", (
        f"second build workflow ended as {final_status!r} instead of COMPLETED; cannot "
        "exercise the post-completion positive control from this run"
    )
    resp = bedrock.start_automated_reasoning_policy_test_workflow(
        policyArn=policy_arn, buildWorkflowId=second_build_id, testCaseIds=[test_case_id]
    )
    assert resp["policyArn"] == policy_arn, (
        f"expected the restored call to echo policyArn={policy_arn!r}, got {resp['policyArn']!r}"
    )


def _create_ar_policy(ctx) -> str:
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-bedrock-arpwf-")
    created = bedrock.create_automated_reasoning_policy(name=name)
    policy_arn = created["policyArn"]
    ctx.on_cleanup(lambda: _safe(
        lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn, force=True)
    ))
    return policy_arn


def _start_ingest_build_workflow(bedrock, policy_arn: str, text: str, document_name: str) -> str:
    resp = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="INGEST_CONTENT",
        sourceContent={
            "workflowContent": {
                "documents": [
                    {
                        "document": text.encode("utf-8"),
                        "documentContentType": "txt",
                        "documentName": document_name,
                    }
                ]
            }
        },
    )
    return resp["buildWorkflowId"]


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _error_detail(fn):
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn, timeout_s: float = 180.0) -> None:
    """Run one teardown call: an already-gone resource is fine, ResourceInUseException (the test
    workflow still holds the policy) is retried every 2 s to the deadline, anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
