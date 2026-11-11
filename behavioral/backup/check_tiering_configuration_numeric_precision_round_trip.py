"""tiering-configuration-numeric-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tiering-configuration-numeric-precision-round-trip"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTieringConfiguration returns the TieringDownSettingsInDays written by
    CreateTieringConfiguration as the same integer, with no float coercion or rounding, including
    for a value that is not a round number."""
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real_tier_prec_").replace("-", "_")

    odd_value = 12347  # deliberately not a round number, within [60, 36500]
    backup.create_tiering_configuration(
        TieringConfiguration={
            "TieringConfigurationName": name,
            "BackupVaultName": "*",
            "ResourceSelection": [
                {
                    "Resources": ["*"],
                    "TieringDownSettingsInDays": odd_value,
                    "ResourceType": "S3",
                }
            ],
        },
        TieringConfigurationTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real_tier_prec"},
    )
    ctx.on_cleanup(lambda: backup.delete_tiering_configuration(TieringConfigurationName=name))

    got = backup.get_tiering_configuration(TieringConfigurationName=name)["TieringConfiguration"]
    selection = got["ResourceSelection"][0]
    value = selection["TieringDownSettingsInDays"]

    assert isinstance(value, int), f"TieringDownSettingsInDays came back as {type(value)}, not int"
    assert value == odd_value, f"TieringDownSettingsInDays round-tripped as {value}, expected {odd_value}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
