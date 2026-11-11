"""update-config-persists-new-spectrum."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-config-persists-new-spectrum"
GROUP = "state"
SERVICES = ["groundstation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfig replaces the spectral parameters of an existing Config and GetConfig reflects
    it. Uses AntennaDownlinkConfig (rather than uplink) because uplink frequencies require a
    separate per-account approval that is unavailable in the test account."""
    gs = ctx.client("groundstation")
    name = ctx.unique_name("sim2real-gs-up-")
    created = gs.create_config(
        name=name,
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 7800.0, "units": "MHz"},
                    "bandwidth": {"value": 1.0, "units": "MHz"},
                }
            }
        },
        tags={"sim2real": "update-config-persists-new-spectrum"},
    )
    config_id = created["configId"]
    config_type = created["configType"]
    ctx.on_cleanup(lambda: gs.delete_config(configId=config_id, configType=config_type))
    assert config_type == "antenna-downlink", f"expected configType antenna-downlink, got {config_type!r}"

    new_name = name + "-updated"
    gs.update_config(
        configId=config_id,
        configType=config_type,
        name=new_name,
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 8100.0, "units": "MHz"},
                    "bandwidth": {"value": 2.0, "units": "MHz"},
                }
            }
        },
    )

    fetched = gs.get_config(configId=config_id, configType=config_type)
    assert fetched["name"] == new_name, f"expected name {new_name!r} after update, got {fetched['name']!r}"
    downlink = fetched["configData"]["antennaDownlinkConfig"]
    got_freq = downlink["spectrumConfig"]["centerFrequency"]["value"]
    assert got_freq == 8100.0, f"expected updated centerFrequency 8100.0, got {got_freq!r}"
    got_bw = downlink["spectrumConfig"]["bandwidth"]["value"]
    assert got_bw == 2.0, f"expected updated bandwidth 2.0, got {got_bw!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
