"""provisioned-limit-invalid-category-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioned-limit-invalid-category-rejected"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetProvisionedLimit rejects an unrecognized Category with InvalidParameterException."""
    idp = ctx.client("cognito-idp")

    valid_definition = {"Attributes": {"Category": "UserCreation"}, "LimitClass": "API_CATEGORY"}
    invalid_definition = {
        "Attributes": {"Category": "NotARealLimitCategory"},
        "LimitClass": "API_CATEGORY",
    }

    # Positive control: a real category succeeds and returns a usable limit.
    ok = idp.get_provisioned_limit(LimitDefinition=valid_definition)["Limit"]
    assert ok["LimitDefinition"]["Attributes"]["Category"] == "UserCreation", (
        f"expected Category 'UserCreation' echoed back, got {ok['LimitDefinition']['Attributes']!r}"
    )
    assert ok["ProvisionedLimitValue"] > 0, (
        f"expected a positive provisioned limit for a recognized category, got {ok['ProvisionedLimitValue']!r}"
    )

    code, message = _rejection(lambda: idp.get_provisioned_limit(LimitDefinition=invalid_definition))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected_message = "Unknown API_CATEGORY category: NotARealLimitCategory"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
