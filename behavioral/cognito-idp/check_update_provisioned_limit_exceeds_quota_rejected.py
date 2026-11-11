"""update-provisioned-limit-exceeds-quota-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-provisioned-limit-exceeds-quota-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_CATEGORY = "UserCreation"
_SAME_VALUE = "Requested value is the same as the current provisioned limit"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """UpdateProvisionedLimit far above any account's ceiling fails with ServiceQuotaExceededException and
    leaves the value unchanged, and an update to the free limit then lands, or is refused as unchanged
    when the value already is the free limit."""
    cognito = ctx.client("cognito-idp")
    limit_definition = {"Attributes": {"Category": _CATEGORY}, "LimitClass": "API_CATEGORY"}

    original = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    original_value = original["ProvisionedLimitValue"]
    free_value = original["FreeLimitValue"]

    def _restore():
        try:
            cognito.update_provisioned_limit(
                LimitDefinition=limit_definition, RequestedLimitValue=original_value
            )
        except ClientError as exc:
            # The value already provisioned is refused as unchanged.
            if (_error_code_of(exc), exc.response["Error"].get("Message")) != (
                "InvalidParameterException", _SAME_VALUE
            ):
                raise

    ctx.on_cleanup(_restore)
    # A category never written accepts the value it reports once; provision it explicitly.
    _restore()

    absurd_value = 2_000_000_000
    code, message = _error(
        lambda: cognito.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=absurd_value
        )
    )
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException for an absurd RequestedLimitValue, got {code}"
    )
    # The ceiling is the account's Service Quotas value, which no read here returns.
    assert message.startswith(f"Requested value {absurd_value} exceeds Service Quota ceiling of "), message

    # Effect absent: the account-level provisioned value was not mutated.
    unchanged = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    assert unchanged["ProvisionedLimitValue"] == original_value, (
        "provisioned limit changed even though the oversized request was rejected"
    )

    # Positive control: writing the free limit proves UpdateProvisionedLimit is otherwise live,
    # so the rejection above was specific to the absurd value; the teardown restores the
    # original. A value already at the free limit is refused as unchanged instead.
    if original_value != free_value:
        control = cognito.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=free_value
        )["Limit"]
        assert control["ProvisionedLimitValue"] == free_value, control
        landed = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
        assert landed["ProvisionedLimitValue"] == free_value, landed
    else:
        code, message = _error(
            lambda: cognito.update_provisioned_limit(
                LimitDefinition=limit_definition, RequestedLimitValue=free_value
            )
        )
        assert (code, message) == ("InvalidParameterException", _SAME_VALUE), (code, message)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the expected refusal; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""
    raise AssertionError(f"expected UpdateProvisionedLimit to be rejected, but it succeeded: {result!r}")


def _error_code_of(exc: ClientError) -> str | None:
    try:
        return exc.response["Error"]["Code"]
    except Exception:
        return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
