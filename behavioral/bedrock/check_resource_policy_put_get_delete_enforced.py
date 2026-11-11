"""resource-policy-put-get-delete-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-policy-put-get-delete-enforced"
GROUP = "server-side"
SERVICES = ["bedrock"]

_NONCONFORMING_MESSAGE = (
    "The provided policy document does not conform to the supported policy formats. For more "
    "information about valid policy document formats, check out the Amazon Bedrock Guardrails "
    "documentation"
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy stores a policy GetResourcePolicy returns exactly; Delete reverts it.

    If every documented guardrail policy shape is rejected, the rejection must be the specific
    ValidationException and leave the policy state unchanged.
    """
    bedrock = ctx.client("bedrock")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    guardrail_id, guardrail_arn = _create_ready_guardrail(ctx)
    # Compare against a baseline: with no policy attached, GetResourcePolicy returns 200 and "{}".
    baseline = _policy_state(bedrock, guardrail_arn)

    # Which documented statement shape PutResourcePolicy accepts varies by account.
    candidate_policies = [
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["bedrock:ApplyGuardrail", "bedrock:GetGuardrail"],
                "Resource": guardrail_arn,
            }],
        },
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["bedrock:ApplyGuardrail", "bedrock:GetGuardrail"],
                "Resource": guardrail_arn,
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": f"o-{account_id[:10]}"}},
            }],
        },
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "bedrock:ApplyGuardrail",
                "Resource": guardrail_arn,
            }],
        },
    ]

    put_resp = None
    put_policy_doc = None
    for policy_doc in candidate_policies:
        try:
            put_resp = bedrock.put_resource_policy(
                resourceArn=guardrail_arn, resourcePolicy=json.dumps(policy_doc)
            )
            put_policy_doc = policy_doc
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            message = getattr(exc, "response", {}).get("Error", {}).get("Message")
            assert code == "ValidationException", (
                "a documented guardrail RBP statement shape should only ever be "
                f"rejected with ValidationException, got {code!r}: {message!r}"
            )
            assert message == _NONCONFORMING_MESSAGE, f"unexpected rejection message: {message!r}"

    if put_resp is None:
        # Every shape was rejected (a per-account gate): the state must be unchanged.
        after = _policy_state(bedrock, guardrail_arn)
        assert after == baseline, (
            "every candidate PutResourcePolicy call was rejected, but the "
            f"resource policy state still changed: before={baseline!r} after={after!r}"
        )
        return

    assert put_resp["resourceArn"] == guardrail_arn, (
        "PutResourcePolicy response resourceArn should echo the target guardrail, "
        f"got {put_resp['resourceArn']!r} vs {guardrail_arn!r}"
    )

    fetched = bedrock.get_resource_policy(resourceArn=guardrail_arn)
    fetched_doc = json.loads(fetched["resourcePolicy"])
    assert fetched_doc == put_policy_doc, (
        "an independent GetResourcePolicy should return the exact document "
        f"that was Put, got {fetched_doc!r} vs {put_policy_doc!r}"
    )

    bedrock.delete_resource_policy(resourceArn=guardrail_arn)

    after_delete = _policy_state(bedrock, guardrail_arn)
    assert after_delete == baseline, (
        "DeleteResourcePolicy should revert the resource policy state to its "
        f"pre-Put baseline, got {after_delete!r} vs baseline {baseline!r}"
    )


def _policy_state(bedrock, guardrail_arn: str) -> str:
    """GetResourcePolicy's policy text, or "ERROR:<code>" if it raises, comparable across calls."""
    try:
        return bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"]
    except Exception as exc:  # noqa: BLE001
        return f"ERROR:{getattr(exc, 'response', {}).get('Error', {}).get('Code')}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last}")


def _create_ready_guardrail(ctx):
    bedrock = ctx.client("bedrock")
    created = bedrock.create_guardrail(
        name=ctx.unique_name("sim2real-gr-policy-"),
        blockedInputMessaging="This input is blocked.",
        blockedOutputsMessaging="This output is blocked.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2real-blocked-word"}]},
        tags=[{"key": "sim2real", "value": "resource-policy-put-get-delete-enforced"}],
    )
    guardrail_id = created["guardrailId"]
    guardrail_arn = created["guardrailArn"]
    ctx.on_cleanup(lambda: _delete_guardrail_best_effort(ctx, guardrail_id))

    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id),
        lambda r: r["status"] == "READY",
        timeout_s=60.0,
        interval_s=3.0,
    )
    return guardrail_id, guardrail_arn


def _delete_guardrail_best_effort(ctx, guardrail_id: str) -> None:
    bedrock = ctx.client("bedrock")
    try:
        bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
