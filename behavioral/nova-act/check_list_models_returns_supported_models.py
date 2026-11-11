"""list-models-returns-supported-models."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-models-returns-supported-models"
GROUP = "control-plane"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListModels echoes the requested clientCompatibilityVersion and returns at least one
    supported model (either directly, or via compatibilityInformation.supportedModelIds)."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)

    resp = nova.list_models(clientCompatibilityVersion=1)

    echoed = resp["compatibilityInformation"]["clientCompatibilityVersion"]
    assert echoed == 1, f"expected ListModels to echo requested clientCompatibilityVersion 1, got {echoed!r}"

    summaries = resp.get("modelSummaries") or []
    supported = resp["compatibilityInformation"].get("supportedModelIds") or []
    assert summaries or supported, "expected at least one model to be reported as available/supported"

    for model in summaries:
        assert model["modelId"], f"model summary missing modelId: {model!r}"
        status = model["modelLifecycle"]["status"]
        assert isinstance(status, str) and status, (
            f"model {model.get('modelId')!r} has invalid modelLifecycle.status {status!r}"
        )
        min_ver = model["minimumCompatibilityVersion"]
        assert isinstance(min_ver, int), (
            f"model {model.get('modelId')!r} minimumCompatibilityVersion is not an int: {min_ver!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
