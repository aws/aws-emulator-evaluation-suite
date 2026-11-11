"""delete-aggregation-authorization-malformed-account-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-aggregation-authorization-malformed-account-rejected"
GROUP = "state-machine"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "identity:standalone", "phase:standalone", "plane:control", "resource:account-singleton:config-aggregation-authorization")
def run(ctx) -> None:
    """DeleteAggregationAuthorization with a non-12-digit AuthorizedAccountId is rejected with
    ValidationException and leaves the authorization listed; deleting it with the correct
    account id then succeeds."""
    config = ctx.client("config")
    account_id = ctx.account
    region = ctx.region

    config.put_aggregation_authorization(
        AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
    )
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            config.delete_aggregation_authorization(
                AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
            )

    ctx.on_cleanup(_cleanup)

    found = _find_authorization(config, account_id, region)
    assert found is not None, "expected the new authorization in DescribeAggregationAuthorizations, got none"

    # The API reference documents InvalidParameterValueException, but AWS answers pattern
    # violations with ValidationException. The id is 12 characters so only the \d{12} pattern
    # fails: two violations are reported in no fixed order.
    malformed = "12345678901x"
    code, message = _error_code(
        lambda: config.delete_aggregation_authorization(
            AuthorizedAccountId=malformed, AuthorizedAwsRegion=region
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        f"1 validation error detected: Value '{malformed}' at 'authorizedAccountId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: \\d{12}"
    ), f"unexpected message: {message!r}"

    # Effect absent: the real authorization is still there, untouched.
    found = _find_authorization(config, account_id, region)
    assert found is not None, "expected the authorization to survive the rejected delete, got none"

    # Positive control: deleting with the correct account id succeeds.
    config.delete_aggregation_authorization(
        AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
    )
    deleted["done"] = True
    found = _find_authorization(config, account_id, region)
    assert found is None, "expected the authorization gone after the delete, it is still listed"


def _error_code(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED (response keys: {sorted(result)})"
    )


def _find_authorization(config, account_id, region):
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = config.describe_aggregation_authorizations(**kwargs)
        for auth in page.get("AggregationAuthorizations", []):
            if (
                auth["AuthorizedAccountId"] == account_id
                and auth["AuthorizedAwsRegion"] == region
            ):
                return auth
        next_token = page.get("NextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
