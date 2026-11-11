"""op-contract-update-provisioned-limit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-provisioned-limit"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """UpdateProvisionedLimit sets a category's provisioned value as GetProvisionedLimit reads it; a value
    beyond the Service Quotas ceiling fails with ServiceQuotaExceededException and leaves the value
    unchanged, and re-requesting the current value fails with InvalidParameterException."""
    cognito = ctx.client("cognito-idp")
    limit_definition = {"Attributes": {"Category": "UserCreation"}, "LimitClass": "API_CATEGORY"}

    before = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    original_value = before["ProvisionedLimitValue"]
    free_limit = before["FreeLimitValue"]

    # This mutates an account-global singleton (the account's provisioned RPS for this
    # API category), so it must be restored to what it was found at, not left at
    # whatever this check last wrote.
    ctx.on_cleanup(lambda: _write_current(cognito, limit_definition, original_value))
    _write_current(cognito, limit_definition, original_value)

    # Round-trip to the pool's own free-tier default: verifies the write path without
    # requesting any billable capacity increase above the free limit. A value already at
    # the free limit is refused as unchanged.
    if original_value != free_limit:
        resp = cognito.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=free_limit
        )["Limit"]
        assert resp["ProvisionedLimitValue"] == free_limit, (
            f"UpdateProvisionedLimit echoed {resp['ProvisionedLimitValue']!r}, expected {free_limit!r}"
        )
    else:
        code, message = _error(
            lambda: cognito.update_provisioned_limit(
                LimitDefinition=limit_definition, RequestedLimitValue=free_limit
            )
        )
        assert (code, message) == ("InvalidParameterException", _SAME_VALUE), (code, message)

    after = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    assert after["ProvisionedLimitValue"] == free_limit, (
        f"GetProvisionedLimit read back {after['ProvisionedLimitValue']!r} after the write, "
        f"expected {free_limit!r}"
    )

    # Error boundary: a value far beyond any realistic account quota ceiling is rejected.
    code, message = _error(
        lambda: cognito.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=2_000_000_000
        )
    )
    assert code == "ServiceQuotaExceededException", (
        f"an absurd RequestedLimitValue returned {code!r}, expected "
        f"'ServiceQuotaExceededException'"
    )
    # The ceiling is the account's Service Quotas value, which no read here returns.
    assert message.startswith("Requested value 2000000000 exceeds Service Quota ceiling of "), message

    # Effect absent: an independent read at the destination proves the rejected write
    # never took hold, rather than trusting the mutating call's own error response.
    unchanged = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    assert unchanged["ProvisionedLimitValue"] == free_limit, (
        f"the provisioned limit is {unchanged['ProvisionedLimitValue']!r} after the rejected "
        f"update, expected it unchanged at {free_limit!r}"
    )


_SAME_VALUE = "Requested value is the same as the current provisioned limit"


def _write_current(cognito, limit_definition, value) -> None:
    """Provision ``value`` explicitly: a category never written accepts the value it reports
    once, and a provisioned one refuses an unchanged value with InvalidParameterException."""
    from botocore.exceptions import ClientError

    try:
        cognito.update_provisioned_limit(LimitDefinition=limit_definition, RequestedLimitValue=value)
    except ClientError as err:
        if (err.response["Error"]["Code"], err.response["Error"].get("Message")) != (
            "InvalidParameterException", _SAME_VALUE
        ):
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message") or ""
    raise AssertionError(
        f"expected UpdateProvisionedLimit to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
