"""antenna-downlink-config-default-polarization."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "antenna-downlink-config-default-polarization"
GROUP = "state"
SERVICES = ["groundstation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SpectrumConfig.polarization defaults server-side to NONE when omitted at creation,
    and does not overwrite a polarization that was set explicitly."""
    gs = ctx.client("groundstation")
    name = ctx.unique_name("sim2real-gs-dl-")
    created = gs.create_config(
        name=name,
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 7850.0, "units": "MHz"},
                    "bandwidth": {"value": 1.0, "units": "MHz"},
                    # polarization intentionally omitted
                }
            }
        },
        tags={"sim2real": "antenna-downlink-config-default-polarization"},
    )
    config_id = created["configId"]
    config_type = created["configType"]
    ctx.on_cleanup(lambda: gs.delete_config(configId=config_id, configType=config_type))

    fetched = gs.get_config(configId=config_id, configType=config_type)
    spectrum = fetched["configData"]["antennaDownlinkConfig"]["spectrumConfig"]
    assert spectrum["polarization"] == "NONE", (
        f"expected server-default polarization NONE when omitted, got {spectrum['polarization']!r}"
    )

    # Positive control: an explicit non-default polarization must persist unchanged, so a
    # target that just hardcodes NONE for every Config cannot pass the assertion above.
    explicit_name = ctx.unique_name("sim2real-gs-dl-explicit-")
    explicit = gs.create_config(
        name=explicit_name,
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 7850.0, "units": "MHz"},
                    "bandwidth": {"value": 1.0, "units": "MHz"},
                    "polarization": "LEFT_HAND",
                }
            }
        },
        tags={"sim2real": "antenna-downlink-config-default-polarization"},
    )
    explicit_id = explicit["configId"]
    explicit_type = explicit["configType"]
    ctx.on_cleanup(lambda: gs.delete_config(configId=explicit_id, configType=explicit_type))

    explicit_fetched = gs.get_config(configId=explicit_id, configType=explicit_type)
    explicit_spectrum = explicit_fetched["configData"]["antennaDownlinkConfig"]["spectrumConfig"]
    assert explicit_spectrum["polarization"] == "LEFT_HAND", (
        f"expected explicit polarization LEFT_HAND to persist unchanged, "
        f"got {explicit_spectrum['polarization']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
