"""dataflow-endpoint-config-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "dataflow-endpoint-config-roundtrip"
GROUP = "crud"
SERVICES = ["groundstation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A dataflow-endpoint type Config persists its dataflowEndpointName/Region exactly."""
    gs = ctx.client("groundstation")
    name = ctx.unique_name("sim2real-gs-dfe-")
    created = gs.create_config(
        name=name,
        configData={
            "dataflowEndpointConfig": {
                "dataflowEndpointName": "downlink-demod-decode-endpoint",
                "dataflowEndpointRegion": ctx.region,
            }
        },
    )
    config_id, config_type = created["configId"], created["configType"]
    ctx.on_cleanup(lambda: gs.delete_config(configId=config_id, configType=config_type))
    assert config_type == "dataflow-endpoint", f"expected configType 'dataflow-endpoint', got {config_type!r}"
    assert created["configArn"].endswith(config_id), (
        f"configArn {created['configArn']!r} does not end with configId {config_id!r}"
    )

    fetched = gs.get_config(configId=config_id, configType=config_type)
    assert fetched["name"] == name, f"expected name {name!r}, got {fetched['name']!r}"
    assert fetched["configType"] == "dataflow-endpoint", (
        f"expected configType 'dataflow-endpoint' on the independent read, got {fetched['configType']!r}"
    )
    dfe = fetched["configData"]["dataflowEndpointConfig"]
    assert dfe["dataflowEndpointName"] == "downlink-demod-decode-endpoint", (
        f"expected dataflowEndpointName to round-trip, got {dfe['dataflowEndpointName']!r}"
    )
    assert dfe["dataflowEndpointRegion"] == ctx.region, (
        f"expected dataflowEndpointRegion {ctx.region!r} to round-trip, got {dfe['dataflowEndpointRegion']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
