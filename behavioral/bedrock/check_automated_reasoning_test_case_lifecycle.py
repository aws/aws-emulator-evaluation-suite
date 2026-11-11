"""automated-reasoning-test-case-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automated-reasoning-test-case-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAutomatedReasoningPolicyTestCase makes the test case gettable and
    DeleteAutomatedReasoningPolicyTestCase causes 404 on subsequent Get."""
    bedrock = ctx.client("bedrock")
    policy_arn = _create_policy(ctx, bedrock)

    created = bedrock.create_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        guardContent=(
            "The employee has worked here for three years on a full-time basis, "
            "so they are eligible for company benefits."
        ),
        expectedAggregatedFindingsResult="VALID",
    )
    test_case_id = created["testCaseId"]

    got = bedrock.get_automated_reasoning_policy_test_case(policyArn=policy_arn, testCaseId=test_case_id)
    test_case = got["testCase"]
    assert test_case["testCaseId"] == test_case_id, f"expected testCaseId {test_case_id!r}, got {test_case['testCaseId']!r}"
    assert test_case["expectedAggregatedFindingsResult"] == "VALID", (
        f"expected expectedAggregatedFindingsResult 'VALID', got {test_case['expectedAggregatedFindingsResult']!r}"
    )
    last_updated_at = test_case["updatedAt"]

    bedrock.delete_automated_reasoning_policy_test_case(
        policyArn=policy_arn, testCaseId=test_case_id, lastUpdatedAt=last_updated_at
    )

    def _probe():
        # A Get that still succeeds is the deletion not yet visible: keep polling.
        try:
            bedrock.get_automated_reasoning_policy_test_case(policyArn=policy_arn, testCaseId=test_case_id)
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        return None

    expected_message = (
        f"The TestCase with testCaseId: {test_case_id} and policyArn: {policy_arn} does not exist"
    )
    code, message = _poll_until(_probe, lambda c: c is not None, timeout_s=60.0, interval_s=2.0)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # a mutation on the now-dead id also fails, not just the read
    update_code, update_message = _error(
        lambda: bedrock.update_automated_reasoning_policy_test_case(
            policyArn=policy_arn,
            testCaseId=test_case_id,
            guardContent="irrelevant, the test case is gone",
            lastUpdatedAt=last_updated_at,
            expectedAggregatedFindingsResult="VALID",
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted test case, got {update_code!r}"
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r} updating a deleted test case, got {update_message!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the refused call; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        name=name, policyDefinition=_minimal_policy_definition()
    )
    policy_arn = resp["policyArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))
    )
    return policy_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
