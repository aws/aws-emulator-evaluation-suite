"""create-list-delete-custom-action-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-list-delete-custom-action-type"
GROUP = 'lifecycle'
SERVICES = ['codepipeline']

def _create_custom_action_type(client, ctx, category="Build"):
    """CreateCustomActionType; register delete cleanup; return the (unique) provider name."""
    provider = ctx.unique_name("sim2real-behav-ca-")
    version = "1"
    resp = client.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    assert resp["actionType"]["id"]["provider"] == provider, resp
    ctx.on_cleanup(
        lambda: client.delete_custom_action_type(category=category, provider=provider, version=version)
    )
    return provider

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCustomActionType -> ListActionTypes (Custom) -> DeleteCustomActionType.

    The created type appears under owner=Custom while present and disappears
    from the list after deletion.
    """
    ev = ctx.client("codepipeline")
    provider = _create_custom_action_type(ev, ctx, )
    def _custom_providers() -> set[str]:
        providers: set[str] = set()
        paginator = ev.get_paginator("list_action_types")
        for page in paginator.paginate(actionOwnerFilter="Custom"):
            for at in page.get("actionTypes", []):
                providers.add(at["id"]["provider"])
        return providers
    assert provider in _custom_providers(), f"{provider} missing from ListActionTypes"
    ev.delete_custom_action_type(category="Build", provider=provider, version="1")
    assert provider not in _custom_providers(), (
        f"{provider} still listed after DeleteCustomActionType"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
