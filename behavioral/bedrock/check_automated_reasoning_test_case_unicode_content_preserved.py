"""automated-reasoning-test-case-unicode-content-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "automated-reasoning-test-case-unicode-content-preserved"
GROUP = "representation"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A test case's unicode/multi-byte guardContent round-trips byte-identical through Get."""
    bedrock = ctx.client("bedrock")

    policy_name = ctx.unique_name("sim2real-arc-policy-")
    policy = bedrock.create_automated_reasoning_policy(
        name=policy_name, tags=[{"key": "sim2real", "value": CHECK}]
    )
    policy_arn = policy["policyArn"]
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))

    guard_content = (
        "拒否されるべき内容: café münchen — refund über $100 requires manager approval. "
        "😀 mixed emoji, Ünïcödé, and CJK 汉字 characters must survive the round trip exactly."
    )
    query_content = "Peut-on approuver un remboursement de 150€ sans signature du responsable? 質問"

    created = bedrock.create_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        guardContent=guard_content,
        queryContent=query_content,
        expectedAggregatedFindingsResult="INVALID",
        confidenceThreshold=0.75,
    )
    test_case_id = created["testCaseId"]

    def _delete_test_case() -> None:
        current = bedrock.get_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id
        )["testCase"]
        bedrock.delete_automated_reasoning_policy_test_case(
            policyArn=policy_arn,
            testCaseId=test_case_id,
            lastUpdatedAt=current["updatedAt"],
        )

    ctx.on_cleanup(_delete_test_case)

    got = bedrock.get_automated_reasoning_policy_test_case(
        policyArn=policy_arn, testCaseId=test_case_id
    )["testCase"]

    assert got["guardContent"] == guard_content, (
        f"guardContent was not preserved byte-identical: {got['guardContent']!r} != {guard_content!r}"
    )
    assert got["queryContent"] == query_content, (
        f"queryContent was not preserved byte-identical: {got['queryContent']!r} != {query_content!r}"
    )
    assert got["expectedAggregatedFindingsResult"] == "INVALID", (
        f"expectedAggregatedFindingsResult was not preserved: {got['expectedAggregatedFindingsResult']!r} != 'INVALID'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
