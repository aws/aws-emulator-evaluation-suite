"""automated-reasoning-policy-version-immutable-snapshot."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "automated-reasoning-policy-version-immutable-snapshot"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy version snapshots the definition: after UpdateAutomatedReasoningPolicy the base
    policy's definitionHash changes while the version ARN keeps reporting the original hash."""
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-arpolicy-")

    empty_definition = {"version": "1", "types": [], "rules": [], "variables": []}
    create_resp = bedrock.create_automated_reasoning_policy(
        name=name,
        policyDefinition=empty_definition,
        tags=[{"key": "sim2real", "value": "arpolicy-version-immutable-snapshot"}],
    )
    base_arn = create_resp["policyArn"]
    hash0 = create_resp["definitionHash"]
    ctx.on_cleanup(lambda: _best_effort_delete(bedrock, base_arn))

    version_resp = bedrock.create_automated_reasoning_policy_version(
        policyArn=base_arn, lastUpdatedDefinitionHash=hash0
    )
    snapshot_arn = version_resp["policyArn"]
    assert snapshot_arn != base_arn, (
        f"expected the version to get its own ARN distinct from the base policy "
        f"{base_arn!r}, got {snapshot_arn!r}"
    )
    assert version_resp["definitionHash"] == hash0, (
        f"expected the freshly created version to snapshot the hash it was created "
        f"with ({hash0!r}), got {version_resp['definitionHash']!r}"
    )

    updated_definition = {
        "version": "1",
        "types": [],
        "rules": [],
        "variables": [
            {
                "name": "TestVar",
                "type": "BOOL",
                "description": "a variable added purely to change the definition hash",
            }
        ],
    }
    update_resp = bedrock.update_automated_reasoning_policy(
        policyArn=base_arn, policyDefinition=updated_definition
    )
    hash1 = update_resp["definitionHash"]
    assert hash1 != hash0, (
        f"expected the update to change the base policy's definitionHash away from "
        f"{hash0!r}, but it reported the same hash {hash1!r}"
    )

    current = bedrock.get_automated_reasoning_policy(policyArn=base_arn)
    assert current["definitionHash"] == hash1, (
        f"expected an independent read of the base policy to report the "
        f"post-update hash {hash1!r}, got {current['definitionHash']!r}"
    )

    snapshot = bedrock.get_automated_reasoning_policy(policyArn=snapshot_arn)
    assert snapshot["definitionHash"] == hash0, (
        f"expected the versioned snapshot to keep reporting its frozen "
        f"pre-update hash {hash0!r} even after the base policy moved to "
        f"{hash1!r}, got {snapshot['definitionHash']!r}"
    )


def _best_effort_delete(bedrock, policy_arn):
    """Delete the policy with its versions; an already-deleted policy needs nothing."""
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_automated_reasoning_policy(policyArn=policy_arn, force=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
