"""update-automated-reasoning-policy-stale-version-rejected."""
from __future__ import annotations

import concurrent.futures
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-automated-reasoning-policy-stale-version-rejected"
GROUP = "concurrency"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAutomatedReasoningPolicyVersion rejects a definitionHash made stale by concurrent
    updates with ConflictException and creates no version, while the current hash creates exactly
    that version: the policy definition is guarded by optimistic concurrency."""
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-arp-")

    skeleton = {"version": "1", "types": [], "rules": [], "variables": []}
    created = bedrock.create_automated_reasoning_policy(
        name=name,
        policyDefinition=skeleton,
        tags=[
            {
                "key": "sim2real",
                "value": "update-automated-reasoning-policy-stale-version-rejected",
            }
        ],
    )
    policy_arn = created["policyArn"]
    h0 = created["definitionHash"]
    ctx.on_cleanup(lambda: _delete_policy_best_effort(ctx, policy_arn))
    assert h0, f"create_automated_reasoning_policy returned no definitionHash: {created!r}"

    def_a = {
        "version": "1",
        "types": [{"name": "ColorA", "values": [{"value": "Red"}]}],
        "rules": [],
        "variables": [],
    }
    def_b = {
        "version": "1",
        "types": [{"name": "ColorB", "values": [{"value": "Blue"}]}],
        "rules": [],
        "variables": [],
    }

    def _update(defn: dict) -> dict:
        return bedrock.update_automated_reasoning_policy(
            policyArn=policy_arn, policyDefinition=defn
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, def_a), pool.submit(_update, def_b)]
        results = [f.result() for f in futures]

    # Both racing updates succeed (Update has no optimistic-lock of its own);
    # the definition has now changed from the h0 captured at creation time.
    for r in results:
        assert r["definitionHash"], f"update_automated_reasoning_policy returned no definitionHash: {r!r}"

    current = bedrock.get_automated_reasoning_policy(policyArn=policy_arn)
    h_current = current["definitionHash"]
    assert h_current != h0, f"definition hash did not change after concurrent updates: still {h0!r}"

    # A policy's first version is always numbered "1", at the ARN suffix ":1".
    first_version_arn = f"{policy_arn}:1"

    # Using the now-stale h0 to create a version must be rejected, and the
    # rejection must leave no version behind -- proved by an independent read
    # at the version's own ARN, not by trusting the failed call's response.
    stale_code, stale_message = _error(
        lambda: bedrock.create_automated_reasoning_policy_version(
            policyArn=policy_arn, lastUpdatedDefinitionHash=h0
        )
    )
    assert stale_code == "ConflictException", (
        f"expected ConflictException for a stale definitionHash, got {stale_code!r}: {stale_message!r}"
    )
    assert stale_message == "Provided definition hash does not match the DRAFT policy definition hash.", f"unexpected rejection message: {stale_message!r}"
    absent_code, absent_message = _error(
        lambda: bedrock.get_automated_reasoning_policy(policyArn=first_version_arn)
    )
    assert absent_code == "ResourceNotFoundException", (
        f"expected no version to exist after the rejected stale create, "
        f"got {absent_code!r} reading {first_version_arn!r}: {absent_message!r}"
    )
    assert absent_message == "Policy version does not exist", f"unexpected not-found message: {absent_message!r}"

    # Positive control: the fresh, current hash is accepted and a version is
    # created -- confirmed by an independent read at the versioned ARN, not
    # just the mutating call's own response.
    version_resp = bedrock.create_automated_reasoning_policy_version(
        policyArn=policy_arn, lastUpdatedDefinitionHash=h_current
    )
    assert version_resp["policyArn"] == first_version_arn, (
        f"expected the first version ARN {first_version_arn!r}, got {version_resp['policyArn']!r}"
    )
    assert version_resp["version"] == "1", f"expected version '1', got {version_resp['version']!r}"

    snapshot = bedrock.get_automated_reasoning_policy(policyArn=first_version_arn)
    assert snapshot["definitionHash"] == h_current, (
        f"versioned snapshot definitionHash {snapshot['definitionHash']!r} does not match "
        f"the current hash {h_current!r} used to create it"
    )
    assert snapshot["version"] == "1", (
        f"expected the versioned read to report version '1', got {snapshot['version']!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises: accepting
    a call AWS refuses is a distinct failure from returning the wrong error code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_policy_best_effort(ctx: Any, policy_arn: str, timeout_s: float = 60.0) -> None:
    """Force-delete the policy and its version; retry ResourceInUseException every 2 s to the
    deadline, return on ResourceNotFoundException, raise anything else."""
    bedrock = ctx.client("bedrock")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            bedrock.delete_automated_reasoning_policy(policyArn=policy_arn, force=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
