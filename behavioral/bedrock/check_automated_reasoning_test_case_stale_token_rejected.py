"""automated-reasoning-test-case-stale-token-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automated-reasoning-test-case-stale-token-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAutomatedReasoningPolicyTestCase with a stale lastUpdatedAt (from before an
    update) is rejected with ConflictException, the test case survives, and deleting with
    the current lastUpdatedAt (positive control) removes it."""
    bedrock = ctx.client("bedrock")
    policy_arn = _create_policy(ctx, bedrock)

    created = bedrock.create_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        guardContent="Full-time employees with over a year of tenure are eligible for benefits.",
        expectedAggregatedFindingsResult="VALID",
    )
    test_case_id = created["testCaseId"]
    got = bedrock.get_automated_reasoning_policy_test_case(policyArn=policy_arn, testCaseId=test_case_id)
    stale_updated_at = got["testCase"]["updatedAt"]

    # Modify the test case so its updatedAt moves forward, staling the token we captured above.
    bedrock.update_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        testCaseId=test_case_id,
        guardContent="Full-time employees with over two years of tenure are eligible for benefits.",
        lastUpdatedAt=stale_updated_at,
        expectedAggregatedFindingsResult="VALID",
    )

    code, message = _error(
        lambda: bedrock.delete_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id, lastUpdatedAt=stale_updated_at
        )
    )
    assert code == "ConflictException", f"expected ConflictException for a stale lastUpdatedAt, got {code!r}"
    expected_conflict = (
        f"Conflict with deleting TestCase with testCaseId: {test_case_id} and policyArn: {policy_arn}"
    )
    assert message == expected_conflict, f"expected message {expected_conflict!r}, got {message!r}"

    # effect absent: the test case is still there after the rejected stale-token delete
    still_there = bedrock.get_automated_reasoning_policy_test_case(policyArn=policy_arn, testCaseId=test_case_id)
    fresh_updated_at = still_there["testCase"]["updatedAt"]
    assert still_there["testCase"]["testCaseId"] == test_case_id, (
        f"expected the rejected delete to leave {test_case_id!r} in place, "
        f"got {still_there['testCase']['testCaseId']!r}"
    )

    # positive control: deleting with the current token succeeds
    bedrock.delete_automated_reasoning_policy_test_case(
        policyArn=policy_arn, testCaseId=test_case_id, lastUpdatedAt=fresh_updated_at
    )

    def _probe():
        # A Get that still succeeds is the deletion not yet visible: keep polling.
        try:
            bedrock.get_automated_reasoning_policy_test_case(policyArn=policy_arn, testCaseId=test_case_id)
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        return None

    expected_missing = (
        f"The TestCase with testCaseId: {test_case_id} and policyArn: {policy_arn} does not exist"
    )
    final_code, final_message = _poll_until(_probe, lambda c: c is not None, timeout_s=60.0, interval_s=2.0)
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {final_code!r}"
    )
    assert final_message == expected_missing, f"expected message {expected_missing!r}, got {final_message!r}"

    # a mutation on the now-dead id also fails, not just the read
    update_code, update_message = _error(
        lambda: bedrock.update_automated_reasoning_policy_test_case(
            policyArn=policy_arn,
            testCaseId=test_case_id,
            guardContent="irrelevant, the test case is gone",
            lastUpdatedAt=fresh_updated_at,
            expectedAggregatedFindingsResult="VALID",
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted test case, got {update_code!r}"
    )
    assert update_message == expected_missing, (
        f"expected message {expected_missing!r} updating a deleted test case, got {update_message!r}"
    )


def _error(fn):
    """A rejection assertion: an unexpected SUCCESS must raise."""
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
        name=name,
        policyDefinition=_minimal_policy_definition(),
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )
    policy_arn = resp["policyArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))
    )
    return policy_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
