"""update-provisioned-limit-excessive-value-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-provisioned-limit-excessive-value-rejected"
GROUP = "representation"
SERVICES = ["cognito-idp"]

_LIMIT_DEFINITION = {"LimitClass": "API_CATEGORY", "Attributes": {"Category": "UserCreation"}}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """UpdateProvisionedLimit far above any account's ceiling fails with ServiceQuotaExceededException and
    leaves the value unchanged, and a write of the free limit then lands as GetProvisionedLimit reads it,
    or is refused as unchanged when the value already is the free limit."""
    cognito = ctx.client("cognito-idp")

    baseline = cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    original_value = baseline["ProvisionedLimitValue"]
    free_value = baseline["FreeLimitValue"]

    ctx.on_cleanup(lambda: _write_current(cognito, original_value))
    # A category never written accepts the value it reports once; provision it explicitly.
    _write_current(cognito, original_value)

    excessive_value = 2_000_000_000  # far beyond any account's approved max RPS for this category
    code, message = _error(
        lambda: cognito.update_provisioned_limit(
            LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=excessive_value
        )
    )
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException for a RequestedLimitValue of "
        f"{excessive_value}, got {code!r}"
    )
    # The ceiling is the account's Service Quotas value, which no read here returns.
    assert message.startswith(f"Requested value {excessive_value} exceeds Service Quota ceiling of "), message

    unchanged = cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    assert unchanged["ProvisionedLimitValue"] == original_value, (
        f"provisioned limit changed from {original_value} to "
        f"{unchanged['ProvisionedLimitValue']} despite the oversized request being rejected"
    )

    # Positive control: a legitimate write of the free limit still succeeds afterwards (the
    # teardown restores the original). A value already at the free limit is refused as unchanged
    # instead. The terminal assertion is an INDEPENDENT read, so a target that accepts writes
    # but never persists them cannot pass this by reflection alone.
    if original_value != free_value:
        cognito.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=free_value)
    else:
        code, message = _error(
            lambda: cognito.update_provisioned_limit(
                LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=free_value
            )
        )
        assert (code, message) == ("InvalidParameterException", _SAME_VALUE), (code, message)
    control = cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION)["Limit"]
    assert control["ProvisionedLimitValue"] == free_value, (
        f"expected the provisioned limit to read back as {free_value} after the "
        f"positive-control update, got {control['ProvisionedLimitValue']}"
    )


_SAME_VALUE = "Requested value is the same as the current provisioned limit"


def _write_current(cognito, value) -> None:
    """Provision ``value`` explicitly: a category never written accepts the value it reports
    once, and a provisioned one refuses an unchanged value with InvalidParameterException."""
    from botocore.exceptions import ClientError

    try:
        cognito.update_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=value)
    except ClientError as exc:
        if (exc.response["Error"]["Code"], exc.response["Error"].get("Message")) != (
            "InvalidParameterException", _SAME_VALUE
        ):
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
