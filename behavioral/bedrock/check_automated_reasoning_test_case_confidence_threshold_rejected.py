"""automated-reasoning-test-case-confidence-threshold-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "automated-reasoning-test-case-confidence-threshold-rejected"
GROUP = "representation"
SERVICES = ["bedrock"]


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutomatedReasoningPolicyTestCase rejects confidenceThreshold=1.5 (outside [0, 1]).

    The error is ValidationException and no test case is created; an in-range create succeeds
    and is listed.
    """
    bedrock = ctx.client("bedrock")

    policy_name = ctx.unique_name("sim2real-arc-negpolicy-")
    policy = bedrock.create_automated_reasoning_policy(
        name=policy_name,
        tags=[{"key": "sim2real", "value": "arc-negpolicy"}],
    )
    policy_arn = policy["policyArn"]
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))

    code, message = _error(
        lambda: bedrock.create_automated_reasoning_policy_test_case(
            policyArn=policy_arn,
            guardContent="Refund of $150 was approved without manager review.",
            expectedAggregatedFindingsResult="INVALID",
            confidenceThreshold=1.5,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for confidenceThreshold=1.5 (outside [0,1]), got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'confidenceThreshold' failed to satisfy "
        "constraint: Member must have value less than or equal to 1"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_failed_create = bedrock.list_automated_reasoning_policy_test_cases(policyArn=policy_arn)[
        "testCases"
    ]
    assert after_failed_create == [], (
        f"a rejected CreateAutomatedReasoningPolicyTestCase must not create a test case, got {after_failed_create!r}"
    )

    # Positive control: an in-range confidenceThreshold is accepted.
    created = bedrock.create_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        guardContent="Refund of $150 was approved without manager review.",
        expectedAggregatedFindingsResult="INVALID",
        confidenceThreshold=0.5,
    )
    test_case_id = created["testCaseId"]

    def _delete_test_case() -> None:
        current = bedrock.get_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id
        )["testCase"]
        bedrock.delete_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id, lastUpdatedAt=current["updatedAt"]
        )

    ctx.on_cleanup(_delete_test_case)

    after_valid_create = bedrock.list_automated_reasoning_policy_test_cases(policyArn=policy_arn)[
        "testCases"
    ]
    assert any(tc["testCaseId"] == test_case_id for tc in after_valid_create), (
        "positive control: a valid confidenceThreshold should have created a listable test case"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
