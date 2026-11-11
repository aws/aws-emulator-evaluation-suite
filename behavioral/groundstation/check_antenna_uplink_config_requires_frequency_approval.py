"""antenna-uplink-config-requires-frequency-approval."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "antenna-uplink-config-requires-frequency-approval"
GROUP = "overly-permissive"
SERVICES = ["groundstation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfig for an AntennaUplinkConfig at an in-band but unapproved centerFrequency raises
    InvalidParameterException ("The specified Uplink Frequency has not been approved.") and lists
    no config, while a downlink config is created.
    """
    gs = ctx.client("groundstation")

    name = ctx.unique_name("sim2real-gs-uplink-")

    def _create_uplink_expect_rejection():
        try:
            gs.create_config(
                name=name,
                configData={
                    "antennaUplinkConfig": {
                        "spectrumConfig": {
                            "centerFrequency": {"value": 2050.5, "units": "MHz"},
                            "polarization": "RIGHT_HAND",
                        },
                        "targetEirp": {"value": 42.0, "units": "dBW"},
                    }
                },
            )
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
        raise AssertionError(
            "CreateConfig unexpectedly accepted an AntennaUplinkConfig with an unapproved "
            "centerFrequency -- the account/service-level approval gate did not fire"
        )

    refused = _create_uplink_expect_rejection()
    # The message names the approval gate, which tells it apart from the numeric-range check and
    # from a generic malformed-parameter rejection that share the same code.
    assert refused == (
        "InvalidParameterException",
        "The specified Uplink Frequency has not been approved.",
    ), f"unexpected refusal for an unapproved uplink frequency: {refused!r}"

    # The rejected Config must not exist under any name/type.
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = gs.list_configs(**kwargs)
        for entry in page.get("configList", []):
            assert entry["name"] != name
        next_token = page.get("nextToken")
        if not next_token:
            break

    # An equivalent AntennaDownlinkConfig (no frequency-approval requirement) succeeds.
    downlink_name = ctx.unique_name("sim2real-gs-downlink-cmp-")
    downlink = gs.create_config(
        name=downlink_name,
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 7850.0, "units": "MHz"},
                    "bandwidth": {"value": 1.0, "units": "MHz"},
                    "polarization": "RIGHT_HAND",
                }
            }
        },
        tags={"sim2real-audit": "antenna-uplink-config-requires-frequency-approval"},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(configId=downlink["configId"], configType=downlink["configType"])
    )
    assert downlink["configType"] == "antenna-downlink"

    # Terminal assertion is an independent read (GetConfig), not the CreateConfig response itself.
    fetched = gs.get_config(configId=downlink["configId"], configType=downlink["configType"])
    assert fetched["name"] == downlink_name
    fetched_spectrum = fetched["configData"]["antennaDownlinkConfig"]["spectrumConfig"]
    assert fetched_spectrum["centerFrequency"]["value"] == 7850.0, (
        f"GetConfig did not reflect the created downlink's centerFrequency: {fetched_spectrum!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
