"""provisioned-limit-update-reflected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioned-limit-update-reflected"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """Once a category's value is provisioned, UpdateProvisionedLimit refuses it as unchanged, and a raise
    by one either shows in UpdateProvisionedLimit and GetProvisionedLimit or, with no Service Quotas
    headroom, is refused with ServiceQuotaExceededException and leaves both reported values unchanged."""

    idp = ctx.client("cognito-idp")
    limit_definition = {"Attributes": {"Category": "UserCreation"}, "LimitClass": "API_CATEGORY"}

    baseline = idp.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    baseline_value = baseline["ProvisionedLimitValue"]
    free_value = baseline["FreeLimitValue"]

    changed_to = None

    def _restore():
        if changed_to is not None:
            idp.update_provisioned_limit(
                LimitDefinition=limit_definition, RequestedLimitValue=baseline_value
            )

    ctx.on_cleanup(_restore)

    # A category never written accepts the value it reports once; writing it here makes the value
    # provisioned, so the same-value request below meets the refusal on every account.
    try:
        idp.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=baseline_value
        )
    except ClientError as e:
        if (e.response["Error"]["Code"], e.response["Error"]["Message"]) != (
            "InvalidParameterException",
            "Requested value is the same as the current provisioned limit",
        ):
            raise

    # Distinguishing control: real AWS rejects a same-value request as a validation error
    # ("Requested value is the same as the current provisioned limit"), a *different* and more
    # specific refusal than "no permission" (NotAuthorizedException) or "no quota headroom"
    # (ServiceQuotaExceededException) -- so a target that just denies or accepts everything
    # fails right here, before anything below leans on the account's quota state.
    try:
        idp.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=baseline_value
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "InvalidParameterException", (
            f"a same-value UpdateProvisionedLimit request raised {code!r}, expected "
            f"InvalidParameterException ('same as current')"
        )
        message = e.response["Error"]["Message"]
        assert message == "Requested value is the same as the current provisioned limit", message
    else:
        raise AssertionError(
            "a same-value UpdateProvisionedLimit request on a provisioned value unexpectedly succeeded; "
            "AWS rejects it with InvalidParameterException ('same as current')"
        )

    increased_value = baseline_value + 1
    try:
        update_resp = idp.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=increased_value
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ServiceQuotaExceededException", (
            f"raising the provisioned limit by 1 raised {code!r}, expected "
            f"ServiceQuotaExceededException when there is no headroom above the account's ceiling"
        )
        # The ceiling is the account's Service Quotas value, which no read here returns.
        message = e.response["Error"]["Message"]
        assert message.startswith(f"Requested value {increased_value} exceeds Service Quota ceiling of "), message

        # No Service-Quotas headroom above the current ceiling: the refusal is now the
        # contract this account can prove, and the value must be left exactly as it was.
        after = idp.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
        assert after["ProvisionedLimitValue"] == baseline_value, (
            f"GetProvisionedLimit reported {after['ProvisionedLimitValue']!r} after a refused "
            f"increase to {increased_value!r} was rejected; a refused change must not take effect"
        )
        assert after["FreeLimitValue"] == free_value, (
            f"FreeLimitValue drifted to {after['FreeLimitValue']!r} from {free_value!r} "
            f"after a refused ProvisionedLimitValue increase"
        )
        return

    # This account had headroom: the increase must be reflected by an independent read.
    changed_to = increased_value
    new_value = increased_value
    assert update_resp["Limit"]["ProvisionedLimitValue"] == new_value, (
        f"UpdateProvisionedLimit echoed {update_resp['Limit']['ProvisionedLimitValue']!r}, "
        f"expected the requested {new_value!r}"
    )
    assert update_resp["Limit"]["FreeLimitValue"] == free_value, (
        f"UpdateProvisionedLimit's FreeLimitValue drifted to "
        f"{update_resp['Limit']['FreeLimitValue']!r} from {free_value!r} after a "
        f"ProvisionedLimitValue-only change"
    )

    after = idp.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"]
    assert after["ProvisionedLimitValue"] == new_value, (
        f"GetProvisionedLimit returned {after['ProvisionedLimitValue']!r} after "
        f"UpdateProvisionedLimit set {new_value!r} (baseline was {baseline_value!r})"
    )
    assert after["LimitDefinition"]["Attributes"]["Category"] == "UserCreation", (
        f"GetProvisionedLimit echoed Category "
        f"{after['LimitDefinition']['Attributes'].get('Category')!r}, expected 'UserCreation'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
