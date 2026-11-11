"""automated-reasoning-test-case-unicode-content-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "automated-reasoning-test-case-unicode-content-round-trip"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode and special characters in a test case's guardContent/queryContent
    written via CreateAutomatedReasoningPolicyTestCase are returned
    byte-identical by GetAutomatedReasoningPolicyTestCase."""
    bedrock = ctx.client("bedrock")

    policy_name = ctx.unique_name("sim2real-arp-")
    policy = bedrock.create_automated_reasoning_policy(
        name=policy_name,
        tags=[{"key": "sim2real", "value": "arp-unicode-roundtrip"}],
    )
    policy_arn = policy["policyArn"]
    ctx.on_cleanup(
        lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)
    )

    guard_content = (
        "\u8fd4\u6b3e\u653f\u7b56\uff1a\u5ba2\u6237\u53ef\u5728 30 \u5929\u5185\u9000\u6b3e "
        "\u2014\u2014 el reembolso es \u00e9lite \U0001f4b0, "
        "\u00fc\u00f1\u00ee\u00e7\u00f8\u2202\u00e9 \u2603\ufe0f "
        "quotes:\"'\\ end."
    )
    query_content = (
        "\u00bfCu\u00e1l es la pol\u00edtica de reembolso? \u00e6\u00e5\u00e7\u9006 "
        "\U0001f9ea test with \u201cfancy quotes\u201d"
    )

    created = bedrock.create_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        guardContent=guard_content,
        queryContent=query_content,
        expectedAggregatedFindingsResult="SATISFIABLE",
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

    fetched = bedrock.get_automated_reasoning_policy_test_case(
        policyArn=policy_arn, testCaseId=test_case_id
    )["testCase"]

    assert fetched["guardContent"] == guard_content, _diff(
        "guardContent", guard_content, fetched["guardContent"]
    )
    assert fetched["queryContent"] == query_content, _diff(
        "queryContent", query_content, fetched["queryContent"]
    )


def _diff(field: str, sent: str, got: str) -> str:
    i = next((i for i, (a, b) in enumerate(zip(sent, got)) if a != b), min(len(sent), len(got)))
    return f"{field}[{i}]: sent={sent[i:i+8]!r} got={got[i:i+8]!r} (lens {len(sent)}/{len(got)})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
