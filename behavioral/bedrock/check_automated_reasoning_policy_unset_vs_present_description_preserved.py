"""automated-reasoning-policy-unset-vs-present-description-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "automated-reasoning-policy-unset-vs-present-description-preserved"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAutomatedReasoningPolicy returns the exact description of a policy created with one and no
    description key at all (not an empty or null placeholder) for a policy created without it.
    """
    bedrock = ctx.client("bedrock")

    with_desc_name = ctx.unique_name("sim2real-behav-arpdesc-present-")
    without_desc_name = ctx.unique_name("sim2real-behav-arpdesc-absent-")
    description_text = "A policy created with an explicit description."

    with_desc = bedrock.create_automated_reasoning_policy(
        name=with_desc_name,
        description=description_text,
        tags=[{"key": "sim2real", "value": "arpdesc-present"}],
    )
    without_desc = bedrock.create_automated_reasoning_policy(
        name=without_desc_name,
        tags=[{"key": "sim2real", "value": "arpdesc-absent"}],
    )

    with_desc_arn = with_desc["policyArn"]
    without_desc_arn = without_desc["policyArn"]
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=with_desc_arn))
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=without_desc_arn))

    got_with = bedrock.get_automated_reasoning_policy(policyArn=with_desc_arn)
    got_without = bedrock.get_automated_reasoning_policy(policyArn=without_desc_arn)

    assert got_with.get("description") == description_text, (
        f"expected description {description_text!r}, got {got_with.get('description')!r}"
    )
    assert "description" not in got_without, f"expected no description key, got {got_without.get('description')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
