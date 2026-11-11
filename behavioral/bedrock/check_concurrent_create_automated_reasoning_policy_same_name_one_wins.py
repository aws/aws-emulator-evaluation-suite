"""concurrent-create-automated-reasoning-policy-same-name-one-wins."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "concurrent-create-automated-reasoning-policy-same-name-one-wins"
GROUP = "concurrency"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing a completed CreateAutomatedReasoningPolicy's name and clientRequestToken returns
    the same policyArn with one policy listed, while a new token with the same name creates a
    second policy with its own ARN: idempotency is keyed on the token, not the name.
    """
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-arp-race-")
    token = ctx.unique_name("sim2reartok").replace("-", "")[:64]
    resource_tags = [{"key": "sim2real", "value": CHECK}]

    first = bedrock.create_automated_reasoning_policy(
        name=name, clientRequestToken=token, tags=resource_tags
    )
    policy_arn = first["policyArn"]
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))

    # Reusing the identical token (and name) after the first call has already completed must be
    # ignored -- same ARN back, no ConflictException, no second resource.
    second = bedrock.create_automated_reasoning_policy(
        name=name, clientRequestToken=token, tags=resource_tags
    )
    assert second["policyArn"] == policy_arn, (
        f"expected idempotency-token reuse to return the same policyArn, "
        f"got {second['policyArn']!r} vs original {policy_arn!r}"
    )

    # Confirm exactly one policy with this name is actually listed -- no duplicate slipped
    # through under the covers even though the token was submitted twice.
    matches = _list_policies_named(bedrock, name)
    assert len(matches) == 1, f"expected exactly one policy named {name!r}, found {matches}"
    assert matches[0]["policyArn"] == policy_arn, (
        f"expected the listed policy named {name!r} to have arn {policy_arn!r}, "
        f"got {matches[0]['policyArn']!r}"
    )

    # Positive control: a DIFFERENT token with the same name is accepted as an independent
    # resource (proving the dedupe above was keyed on the token, not silently on the name).
    other_token = ctx.unique_name("sim2reartokb").replace("-", "")[:64]
    other = bedrock.create_automated_reasoning_policy(
        name=name, clientRequestToken=other_token, tags=resource_tags
    )
    other_arn = other["policyArn"]
    assert other_arn != policy_arn, (
        f"expected a different clientRequestToken to mint an independent policy, "
        f"got the same policyArn {other_arn!r} back"
    )
    ctx.on_cleanup(lambda: bedrock.delete_automated_reasoning_policy(policyArn=other_arn))

    # List again: BOTH policies are visible under the shared name, so the token-keyed dedupe did
    # not collapse the policy created with a different token.
    final_matches = _list_policies_named(bedrock, name)
    final_arns = {p["policyArn"] for p in final_matches}
    assert final_arns == {policy_arn, other_arn}, (
        f"expected both {policy_arn!r} and {other_arn!r} listed under name {name!r}, "
        f"got {final_arns}"
    )


def _list_policies_named(bedrock, name: str) -> list:
    matches = []
    paginator = bedrock.get_paginator("list_automated_reasoning_policies")
    for page in paginator.paginate():
        matches.extend(
            p
            for p in page.get("automatedReasoningPolicySummaries", [])
            if p.get("name") == name
        )
    return matches


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


