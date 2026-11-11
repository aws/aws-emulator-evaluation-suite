"""provisioned-limit-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "provisioned-limit-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["cognito-idp"]

_LIMIT_DEFINITION = {"LimitClass": "API_CATEGORY", "Attributes": {"Category": "UserCreation"}}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """UpdateProvisionedLimit's RequestedLimitValue round-trips via GetProvisionedLimit as the exact
    integer, and a request one above the ceiling is refused with the quota error or echoed exactly.
    """
    idp = ctx.client("cognito-idp")

    before = idp.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    default_value = before["FreeLimitValue"]
    original_provisioned = before.get("ProvisionedLimitValue")
    assert isinstance(default_value, int)

    def _restore() -> None:
        if original_provisioned is not None and original_provisioned != default_value:
            idp.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=original_provisioned)

    ctx.on_cleanup(_restore)

    # Re-requesting the current value is refused as a no-op ("Requested value is the same as the
    # current provisioned limit"), so an account already at its default asserts that refusal.
    if original_provisioned == default_value:
        try:
            idp.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=default_value)
        except idp.exceptions.InvalidParameterException as exc:
            message = exc.response["Error"].get("Message")
            assert message == "Requested value is the same as the current provisioned limit", (
                f"expected the same-value-as-current refusal, got a different InvalidParameterException: {exc}"
            )
        else:
            raise AssertionError(
                f"UpdateProvisionedLimit accepted RequestedLimitValue={default_value!r} even though it "
                "already equals the current ProvisionedLimitValue -- real AWS rejects this as a no-op"
            )
    else:
        updated = idp.update_provisioned_limit(
            LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=default_value
        )["Limit"]
        assert updated["ProvisionedLimitValue"] == default_value, (
            f"UpdateProvisionedLimit echoed {updated['ProvisionedLimitValue']!r}, expected the exact integer {default_value!r}"
        )
        assert isinstance(updated["ProvisionedLimitValue"], int)

    after = idp.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    assert after["ProvisionedLimitValue"] == default_value, (
        f"GetProvisionedLimit returned {after['ProvisionedLimitValue']!r}, expected the exact integer {default_value!r}"
    )
    assert isinstance(after["ProvisionedLimitValue"], int)
    assert after["LimitDefinition"] == _LIMIT_DEFINITION

    # Values must lie between the default and the account maximum in Service Quotas; without a
    # quota increase the ceiling equals the default, so default + 1 is usually refused.
    probe_value = default_value + 1
    try:
        probed = idp.update_provisioned_limit(
            LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=probe_value
        )["Limit"]
    except idp.exceptions.ServiceQuotaExceededException as exc:
        # Values from the default up are accepted, so refusing default + 1 puts the ceiling at the default.
        quota_message = exc.response["Error"].get("Message")
        expected = f"Requested value {probe_value} exceeds Service Quota ceiling of {default_value}"
        assert quota_message == expected, (
            f"ServiceQuotaExceededException should name the requested and ceiling values, got: {exc}"
        )
        reread = idp.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
        assert reread["ProvisionedLimitValue"] == default_value, (
            f"a refused UpdateProvisionedLimit must not change the persisted value, "
            f"got {reread['ProvisionedLimitValue']!r} expected {default_value!r}"
        )
    else:
        assert probed["ProvisionedLimitValue"] == probe_value, (
            f"UpdateProvisionedLimit echoed {probed['ProvisionedLimitValue']!r}, expected the exact integer {probe_value!r}"
        )
        assert isinstance(probed["ProvisionedLimitValue"], int)
        reread = idp.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
        assert reread["ProvisionedLimitValue"] == probe_value, (
            f"GetProvisionedLimit returned {reread['ProvisionedLimitValue']!r} after setting {probe_value!r}"
        )
        assert isinstance(reread["ProvisionedLimitValue"], int)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
