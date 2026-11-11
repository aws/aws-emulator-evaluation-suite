"""create-automated-reasoning-policy-duplicate-name-succeeds."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-automated-reasoning-policy-duplicate-name-succeeds"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAutomatedReasoningPolicy accepts a duplicate `name`: both calls succeed and mint two
    distinct, independently readable policies, because `name` is not a uniqueness key here."""
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-bedrock-arp-")

    created = bedrock.create_automated_reasoning_policy(name=name)
    policy_arn = created["policyArn"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)))

    # break exactly one thing: reuse the exact same name -- real Bedrock allows it
    created2 = bedrock.create_automated_reasoning_policy(name=name)
    policy_arn2 = created2["policyArn"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn2)))

    assert policy_arn2 != policy_arn, "a same-name create must mint a genuinely distinct policy, not reuse one"

    # both policies are independently real and addressable -- this wasn't a silent
    # no-op or an overwrite of the first
    first = bedrock.get_automated_reasoning_policy(policyArn=policy_arn)
    second = bedrock.get_automated_reasoning_policy(policyArn=policy_arn2)
    assert first["name"] == name, f"expected first policy's own name to be {name!r}, got {first['name']!r}"
    assert second["name"] == name, f"expected second policy's own name to be {name!r}, got {second['name']!r}"
    assert first["policyArn"] != second["policyArn"], (
        f"independent reads must confirm two distinct policies, got the same arn {first['policyArn']!r} twice"
    )


def _safe(fn) -> None:
    """Run a teardown delete; return only when the policy is already gone."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
