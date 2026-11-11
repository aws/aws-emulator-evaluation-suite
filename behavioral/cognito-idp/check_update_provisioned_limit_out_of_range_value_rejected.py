"""update-provisioned-limit-out-of-range-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-provisioned-limit-out-of-range-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_CATEGORY = "UserAuthentication"  # an adjustable category per Cognito's quotas documentation
_ABSURD_VALUE = 2_000_000_000  # far beyond any account's realistic Service Quotas ceiling


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """UpdateProvisionedLimit rejects a value far beyond the account's Service Quotas range with
    ServiceQuotaExceededException and leaves the provisioned limit unchanged, while re-applying
    the current in-range value succeeds."""
    cognito = ctx.client("cognito-idp")

    baseline = cognito.get_provisioned_limit(
        LimitDefinition={"LimitClass": "API_CATEGORY", "Attributes": {"Category": _CATEGORY}}
    )["Limit"]
    current_value = baseline.get("ProvisionedLimitValue", baseline["FreeLimitValue"])

    control = cognito.update_provisioned_limit(
        LimitDefinition={"LimitClass": "API_CATEGORY", "Attributes": {"Category": _CATEGORY}},
        RequestedLimitValue=current_value,
    )["Limit"]
    assert control["ProvisionedLimitValue"] == current_value, (
        f"positive control failed: re-applying the current value {current_value} was not accepted, "
        f"got {control['ProvisionedLimitValue']}"
    )

    code = _error_code(
        lambda: cognito.update_provisioned_limit(
            LimitDefinition={"LimitClass": "API_CATEGORY", "Attributes": {"Category": _CATEGORY}},
            RequestedLimitValue=_ABSURD_VALUE,
        )
    )
    assert code == "ServiceQuotaExceededException", f"expected ServiceQuotaExceededException, got {code}"

    after = cognito.get_provisioned_limit(
        LimitDefinition={"LimitClass": "API_CATEGORY", "Attributes": {"Category": _CATEGORY}}
    )["Limit"]
    after_value = after.get("ProvisionedLimitValue", after["FreeLimitValue"])
    assert after_value == current_value, f"provisioned limit changed: {current_value} -> {after_value}"


def _error_code(fn):
    """Call fn() and return its botocore error code; raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
