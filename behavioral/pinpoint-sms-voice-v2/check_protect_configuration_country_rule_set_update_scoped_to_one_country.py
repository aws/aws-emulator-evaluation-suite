"""protect-configuration-country-rule-set-update-scoped-to-one-country."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "protect-configuration-country-rule-set-update-scoped-to-one-country"
GROUP = "accumulated-state"
SERVICES = ["pinpoint-sms-voice-v2"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Updating a protect configuration's country rule set for one ISO country changes
    only that country's entry; every other country's rule is read back unchanged.
    """
    client = ctx.client("pinpoint-sms-voice-v2")

    pc = client.create_protect_configuration()
    pc_id = pc["ProtectConfigurationId"]
    ctx.on_cleanup(
        _teardown(
            lambda: client.delete_protect_configuration(ProtectConfigurationId=pc_id),
            "ResourceNotFoundException",
        )
    )

    before = client.get_protect_configuration_country_rule_set(
        ProtectConfigurationId=pc_id,
        NumberCapability="SMS",
    )["CountryRuleSet"]
    new_status = "ALLOW" if before["US"]["ProtectStatus"] != "ALLOW" else "BLOCK"

    client.update_protect_configuration_country_rule_set(
        ProtectConfigurationId=pc_id,
        NumberCapability="SMS",
        CountryRuleSetUpdates={"US": {"ProtectStatus": new_status}},
    )

    after = client.get_protect_configuration_country_rule_set(
        ProtectConfigurationId=pc_id,
        NumberCapability="SMS",
    )["CountryRuleSet"]
    assert after["US"]["ProtectStatus"] == new_status, (
        f"expected US to become {new_status!r}, got {after['US']!r}"
    )

    untouched = {country: rule for country, rule in after.items() if country != "US"}
    expected_untouched = {country: rule for country, rule in before.items() if country != "US"}
    assert untouched == expected_untouched, (
        "updating US must leave every other country's rule unchanged; "
        f"{sum(1 for c in untouched if untouched[c] != expected_untouched.get(c))} countries differ"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
