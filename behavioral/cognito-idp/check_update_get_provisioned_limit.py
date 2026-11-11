"""update-get-provisioned-limit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-get-provisioned-limit"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """UpdateProvisionedLimit changes are enforced and reflected by a subsequent GetProvisionedLimit."""
    from botocore.exceptions import ClientError

    cognito = ctx.client("cognito-idp")

    limit_definition = {
        "LimitClass": "API_CATEGORY",
        "Attributes": {"Category": "UserCreation"},
    }

    try:
        before = cognito.get_provisioned_limit(LimitDefinition=limit_definition)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "NotAuthorizedException"):
            raise AssertionError(
                f"caller lacks permission for GetProvisionedLimit: {code}"
            )
        raise

    original_value = before["Limit"]["ProvisionedLimitValue"]
    free_value = before["Limit"]["FreeLimitValue"]
    assert isinstance(original_value, int) and original_value >= 0, (
        f"expected a non-negative int ProvisionedLimitValue, got {original_value!r}"
    )
    assert before["Limit"]["LimitDefinition"]["Attributes"]["Category"] == "UserCreation", (
        f"GetProvisionedLimit echoed the wrong category: {before['Limit']['LimitDefinition']!r}"
    )

    def _restore():
        # AWS refuses a write of the value already provisioned, so restore only a changed value.
        current = cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"][
            "ProvisionedLimitValue"
        ]
        if current != original_value:
            cognito.update_provisioned_limit(
                LimitDefinition=limit_definition, RequestedLimitValue=original_value
            )

    ctx.on_cleanup(_restore)

    def _update(value):
        """Attempt RequestedLimitValue=value; return (response, None) or (None, (code, message))."""
        try:
            return cognito.update_provisioned_limit(
                LimitDefinition=limit_definition, RequestedLimitValue=value
            ), None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "NotAuthorizedException"):
                raise AssertionError(
                    f"caller lacks permission for UpdateProvisionedLimit: {code}"
                )
            return None, (code, e.response["Error"].get("Message"))

    def _get_value():
        return cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"][
            "ProvisionedLimitValue"
        ]

    # This account's headroom to actually MOVE the value is not knowable in advance -- UserCreation
    # is a self-service-adjustable quota (default free/floor 50 RPS), so a fresh account has zero
    # headroom in EITHER direction until AWS grants an increase (confirmed empirically: even
    # re-submitting the unchanged value is itself rejected with InvalidParameterException when the
    # free floor and the quota ceiling coincide -- RequestedLimitValue must be strictly greater than
    # FreeLimitValue), while an aged/adjusted account may have real headroom. Probe empirically
    # rather than assume either: a stub that ignores writes, or one that accepts an over-quota
    # write, both fail one of the two branches below.
    up_resp, up_err = _update(original_value + 1)
    if up_err is None:
        new_value = original_value + 1
        update_resp = up_resp
    else:
        up_code, up_message = up_err
        assert up_code == "ServiceQuotaExceededException", (
            f"expected ServiceQuotaExceededException requesting {original_value + 1} "
            f"above the account's ceiling, got {up_code}"
        )
        # A rejected original+1 pins the ceiling at the current value.
        expected_up_message = (
            f"Requested value {original_value + 1} exceeds Service Quota ceiling of {original_value}"
        )
        assert up_message == expected_up_message, (
            f"expected the exact over-ceiling message {expected_up_message!r}, got {up_message!r}"
        )
        assert _get_value() == original_value, (
            "a rejected over-ceiling UpdateProvisionedLimit must not change the account's "
            "provisioned value"
        )

        down_resp, down_err = _update(original_value - 1)
        if down_err is None:
            new_value = original_value - 1
            update_resp = down_resp
        else:
            down_code, down_message = down_err
            assert down_code == "InvalidParameterException", (
                f"expected InvalidParameterException requesting {original_value - 1} "
                f"below the account's free/default floor, got {down_code}"
            )
            expected_down_message = (
                f"Requested value {original_value - 1} is below the free limit of {free_value}"
            )
            assert down_message == expected_down_message, (
                f"expected the exact below-floor message {expected_down_message!r}, "
                f"got {down_message!r}"
            )
            assert _get_value() == original_value, (
                "a rejected below-floor UpdateProvisionedLimit must not change the "
                "account's provisioned value"
            )
            # No headroom in either direction: the account's provisioned value is
            # genuinely pinned at its free/default floor and ceiling, so no
            # RequestedLimitValue is valid. The two distinct, specific refusal codes
            # above -- against the successful GetProvisionedLimit that opened this
            # check -- are the full, deterministic contract for this account state.
            return

    assert update_resp["Limit"]["ProvisionedLimitValue"] == new_value, (
        f"UpdateProvisionedLimit did not echo the requested value {new_value}: "
        f"{update_resp['Limit']!r}"
    )
    assert update_resp["Limit"]["FreeLimitValue"] == free_value, (
        f"FreeLimitValue changed from {free_value} to "
        f"{update_resp['Limit']['FreeLimitValue']!r} after an unrelated provisioned-value update"
    )
    assert _get_value() == new_value, (
        "UpdateProvisionedLimit was not reflected by a subsequent GetProvisionedLimit: "
        f"expected {new_value}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
