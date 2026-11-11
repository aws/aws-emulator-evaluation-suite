"""custom-action-type-id-fields-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-action-type-id-fields-reflected"
GROUP = 'lifecycle'
SERVICES = ['codepipeline']

def _track_action_type(client, ctx, category, provider, version):
    """Register a best-effort DeleteCustomActionType cleanup for a manually-created action type."""
    ctx.on_cleanup(
        lambda: client.delete_custom_action_type(category=category, provider=provider, version=version)
    )

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCustomActionType returns the ActionTypeId with owner Custom and the artifact bounds,
    and ListActionTypes returns the same persisted fields."""
    ev = ctx.client("codepipeline")
    provider = ctx.unique_name("sim2real-behav-ca-")
    resp = ev.create_custom_action_type(
        category="Build",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        tags=[{"key": "sim2real-behav-check", "value": CHECK}],
    )
    _track_action_type(ev, ctx, "Build", provider, "1")
    at = resp["actionType"]
    assert at["id"]["category"] == "Build", at
    assert at["id"]["owner"] == "Custom", at
    assert at["id"]["provider"] == provider, at
    assert at["id"]["version"] == "1", at
    assert at["inputArtifactDetails"] == {"minimumCount": 0, "maximumCount": 1}, at
    assert at["outputArtifactDetails"] == {"minimumCount": 0, "maximumCount": 1}, at

    listed = None
    paginator = ev.get_paginator("list_action_types")
    for page in paginator.paginate(actionOwnerFilter="Custom"):
        for candidate in page.get("actionTypes", []):
            if candidate["id"]["provider"] == provider:
                listed = candidate
                break
        if listed is not None:
            break
    assert listed is not None, f"{provider} missing from ListActionTypes(actionOwnerFilter='Custom')"
    assert listed["id"]["category"] == "Build", listed
    assert listed["id"]["owner"] == "Custom", listed
    assert listed["id"]["provider"] == provider, listed
    assert listed["id"]["version"] == "1", listed
    assert listed["inputArtifactDetails"] == {"minimumCount": 0, "maximumCount": 1}, listed
    assert listed["outputArtifactDetails"] == {"minimumCount": 0, "maximumCount": 1}, listed


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
