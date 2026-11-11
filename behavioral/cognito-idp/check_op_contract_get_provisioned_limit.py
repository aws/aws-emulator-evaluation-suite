"""op-contract-get-provisioned-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-provisioned-limit"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetProvisionedLimit returns the account-level rate-limit definition for a known,
    adjustable API category, and rejects a LimitDefinition with an unrecognized
    Category value."""
    idp = ctx.client("cognito-idp")

    # success path: a recognized, adjustable rate-limit category echoes its own definition
    resp = idp.get_provisioned_limit(
        LimitDefinition={"LimitClass": "API_CATEGORY", "Attributes": {"Category": "UserAuthentication"}}
    )
    limit = resp["Limit"]
    assert limit["LimitDefinition"]["LimitClass"] == "API_CATEGORY", limit["LimitDefinition"]
    assert limit["LimitDefinition"]["Attributes"]["Category"] == "UserAuthentication", limit["LimitDefinition"]
    # FreeLimitValue is AWS's fixed free-tier constant for this category, identical across
    # accounts and never raised by UpdateProvisionedLimit;
    # ProvisionedLimitValue is the account's current (adjustable) ceiling and never sits below it.
    assert limit["FreeLimitValue"] == 120, f"expected the API_CATEGORY/UserAuthentication free limit to be 120, got {limit['FreeLimitValue']!r}"
    assert isinstance(limit["ProvisionedLimitValue"], int) and limit["ProvisionedLimitValue"] >= limit["FreeLimitValue"], (
        f"ProvisionedLimitValue {limit['ProvisionedLimitValue']!r} must be >= FreeLimitValue {limit['FreeLimitValue']!r}"
    )

    # distinct error boundary: an unrecognized Category value is rejected
    code, message = _error(
        lambda: idp.get_provisioned_limit(
            LimitDefinition={"LimitClass": "API_CATEGORY", "Attributes": {"Category": "NotARealCategory"}}
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected = "Unknown API_CATEGORY category: NotARealCategory"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
