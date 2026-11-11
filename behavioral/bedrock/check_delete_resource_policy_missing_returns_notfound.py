"""delete-resource-policy-missing-returns-notfound."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-resource-policy-missing-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a guardrail with no resource policy, GetResourcePolicy returns '{}', two
    DeleteResourcePolicy calls both succeed, and the guardrail stays readable with policy '{}':
    deleting a missing policy is an idempotent no-op, not ResourceNotFoundException.
    """
    bedrock = ctx.client("bedrock")

    guardrail_name = ctx.unique_name("sim2real-bedrock-rp-gr-")
    created = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Sorry, this input is blocked.",
        blockedOutputsMessaging="Sorry, this output is blocked.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realforbiddenword"}]},
    )
    guardrail_id = created["guardrailId"]
    guardrail_arn = created["guardrailArn"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)))

    # positive confirmation, not an assumption: GetResourcePolicy on this exact,
    # never-had-a-policy guardrail must succeed (not raise) and report an empty
    # policy document, proving the "missing" case below is genuinely being exercised.
    before_policy = bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"]
    assert json.loads(before_policy) == {}, (
        f"expected an empty resource policy document before any PutResourcePolicy, "
        f"got {before_policy!r}"
    )

    # negative: no resource policy has ever been attached to this guardrail --
    # delete-of-nothing still succeeds (idempotent no-op), it does not error
    # (a ClientError here fails the check with its own code and message)
    bedrock.delete_resource_policy(resourceArn=guardrail_arn)

    # repeat: still a silent no-op, not a one-shot fluke
    bedrock.delete_resource_policy(resourceArn=guardrail_arn)

    # the resource itself (as opposed to the never-attached policy) remains
    # genuinely reachable
    still_there = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
    assert still_there["guardrailId"] == guardrail_id, (
        f"expected guardrail {guardrail_id!r} to remain reachable after two no-op "
        f"DeleteResourcePolicy calls, got {still_there.get('guardrailId')!r}"
    )

    # and GetResourcePolicy still succeeds with an empty document afterwards -- the
    # two no-op deletes did not somehow leave behind a non-empty policy record
    after_policy = bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"]
    assert json.loads(after_policy) == {}, (
        f"expected the resource policy to remain empty after the no-op deletes, "
        f"got {after_policy!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
