"""list-identity-pools-max-results-invalid-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-identity-pools-max-results-invalid-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListIdentityPools accepts MaxResults=60, the documented maximum, and rejects 61 with
    ValidationException and the exact constraint message."""
    ci = ctx.client("cognito-identity")

    # Positive control: the maximum in-range value is accepted.
    control = ci.list_identity_pools(MaxResults=60)
    assert "IdentityPools" in control, f"expected IdentityPools in response, got {control!r}"

    code_too_high, message = _error(lambda: ci.list_identity_pools(MaxResults=61))
    # The QueryLimit shape's range constraint (1-60) is enforced at the request-validation layer
    # on real AWS, which reports it as a generic ValidationException rather than the operation's
    # modeled InvalidParameterException.
    assert code_too_high == "ValidationException", f"expected ValidationException, got {code_too_high}"
    expected = (
        "1 validation error detected: Value '61' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 60"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
