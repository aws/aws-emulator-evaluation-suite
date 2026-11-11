"""default-capacity-providers-active."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "default-capacity-providers-active"
GROUP = 'capacity-provider'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The built-in FARGATE / FARGATE_SPOT capacity providers exist and are
    reported ACTIVE by DescribeCapacityProviders."""
    ecs = ctx.client("ecs")
    resp = ecs.describe_capacity_providers(
        capacityProviders=["FARGATE", "FARGATE_SPOT"]
    )
    providers = {p["name"]: p for p in resp.get("capacityProviders", [])}
    for name in ("FARGATE", "FARGATE_SPOT"):
        assert name in providers, (
            f"built-in {name} capacity provider missing: {resp}"
        )
        assert providers[name]["status"] == "ACTIVE", (
            f"{name} should be ACTIVE, got {providers[name]['status']}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
