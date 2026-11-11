"""create-config-tracking-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-config-tracking-roundtrip"
GROUP = "crud"
SERVICES = ["groundstation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfig persists a TrackingConfig's autotrack value and its tags; both round-trip via
    GetConfig, an independent read issued through a different operation than the create."""
    gs = ctx.client("groundstation")
    name = ctx.unique_name("sim2real-gs-cfg-")
    created = gs.create_config(
        name=name,
        configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        tags={"sim2real": "roundtrip"},
    )
    config_id = created["configId"]
    config_type = created["configType"]
    ctx.on_cleanup(lambda: gs.delete_config(configId=config_id, configType=config_type))

    assert config_type == "tracking", f"expected configType 'tracking', got {config_type!r}"
    assert created["configArn"].endswith(config_id), (
        f"expected configArn to end with {config_id!r}, got {created['configArn']!r}"
    )

    fetched = gs.get_config(configId=config_id, configType=config_type)
    assert fetched["name"] == name, f"expected name {name!r}, got {fetched['name']!r}"
    assert fetched["configType"] == "tracking", (
        f"expected configType 'tracking' on GetConfig, got {fetched['configType']!r}"
    )
    autotrack = fetched["configData"]["trackingConfig"]["autotrack"]
    assert autotrack == "REQUIRED", f"expected autotrack 'REQUIRED', got {autotrack!r}"
    assert fetched["tags"] == {"sim2real": "roundtrip"}, (
        f"expected tags to round-trip, got {fetched['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
