"""update-protect-configuration-country-rule-set-invalid-country-code-denied."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-protect-configuration-country-rule-set-invalid-country-code-denied"
GROUP = "overly-permissive"
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A country rule set update keyed by an ISO code that does not exist is refused,
    and the rule set is left untouched; a well-formed update right after still works.
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

    code, message = _error(
        lambda: client.update_protect_configuration_country_rule_set(
            ProtectConfigurationId=pc_id,
            NumberCapability="SMS",
            CountryRuleSetUpdates={"ZZ": {"ProtectStatus": "BLOCK"}},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an invalid ISO code, got {code!r}"
    )
    expected_message = (
        'Validation Error Occurred - Reason="INVALID_PARAMETER" Fields="countryRuleSetUpdates"'
    )
    assert message == expected_message, f"unexpected message {message!r}"

    after = client.get_protect_configuration_country_rule_set(
        ProtectConfigurationId=pc_id,
        NumberCapability="SMS",
    )["CountryRuleSet"]
    assert after == before, "a rejected update must leave the country rule set exactly as it was"
    assert "ZZ" not in after, (
        f"the invalid code must never appear in the rule set, got keys {sorted(after)!r}"
    )

    # Positive control: a well-formed update right after the refusal still succeeds.
    new_status = "ALLOW" if before["US"]["ProtectStatus"] != "ALLOW" else "BLOCK"
    client.update_protect_configuration_country_rule_set(
        ProtectConfigurationId=pc_id,
        NumberCapability="SMS",
        CountryRuleSetUpdates={"US": {"ProtectStatus": new_status}},
    )
    confirmed = client.get_protect_configuration_country_rule_set(
        ProtectConfigurationId=pc_id,
        NumberCapability="SMS",
    )["CountryRuleSet"]
    assert confirmed["US"]["ProtectStatus"] == new_status, (
        f"positive control failed: expected US {new_status!r}, got {confirmed['US']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
