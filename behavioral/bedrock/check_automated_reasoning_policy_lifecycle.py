"""automated-reasoning-policy-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automated-reasoning-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAutomatedReasoningPolicy makes the policy gettable and
    DeleteAutomatedReasoningPolicy causes subsequent Get to 404."""
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-arp-")

    resp = bedrock.create_automated_reasoning_policy(
        name=name, policyDefinition=_minimal_policy_definition()
    )
    policy_arn = resp["policyArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)))

    got = bedrock.get_automated_reasoning_policy(policyArn=policy_arn)
    assert got["policyArn"] == policy_arn, f"expected policyArn {policy_arn!r}, got {got['policyArn']!r}"
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    # Newly created policies start on the mutable working draft, not a numbered version.
    assert got["version"] == "DRAFT", f"expected version 'DRAFT', got {got['version']!r}"

    bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)

    def _probe():
        # A Get that still succeeds is the deletion not yet visible: keep polling.
        try:
            bedrock.get_automated_reasoning_policy(policyArn=policy_arn)
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        return None

    code, message = _poll_until(_probe, lambda c: c is not None, timeout_s=60.0, interval_s=2.0)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Get on a deleted policy, got {code!r}"
    )
    assert message == "Policy does not exist", (
        f"expected Get on a deleted policy to say 'Policy does not exist', got {message!r}"
    )

    # The deleted id is not just unreadable -- it is unusable: a mutation against it
    # must also fail with the same not-found code, not silently resurrect the policy.
    update_code, update_message = _error(
        lambda: bedrock.update_automated_reasoning_policy(
            policyArn=policy_arn, policyDefinition=_minimal_policy_definition()
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Update on a deleted policy, got {update_code!r}"
    )
    assert update_message == "Policy was not found", (
        f"expected Update on a deleted policy to say 'Policy was not found', got {update_message!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
