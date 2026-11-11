"""list-identities-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-identities-max-results-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListIdentities with MaxResults outside the documented 1-60 range is rejected by the service
    with ValidationException; an in-range call succeeds."""
    cip = ctx.client("cognito-identity")
    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name, AllowUnauthenticatedIdentities=True
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))
    cip.get_id(IdentityPoolId=pool_id)

    control = cip.list_identities(IdentityPoolId=pool_id, MaxResults=1)
    assert "Identities" in control, f"expected a successful response to carry Identities, got {control!r}"

    raw = ctx.client("cognito-identity", config=Config(parameter_validation=False))

    # The SDK enforces the same 1-60 bound client-side, so the out-of-range calls use a client
    # with parameter validation disabled to reach the service.
    code_zero, message_zero = _error(
        lambda: raw.list_identities(IdentityPoolId=pool_id, MaxResults=0)
    )
    assert code_zero == "ValidationException", f"expected ValidationException, got {code_zero}"
    expected_zero = (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message_zero == expected_zero, (
        f"expected message {expected_zero!r}, got {message_zero!r}"
    )

    code_over, message_over = _error(
        lambda: raw.list_identities(IdentityPoolId=pool_id, MaxResults=1000)
    )
    assert code_over == "ValidationException", f"expected ValidationException, got {code_over}"
    expected_over = (
        "1 validation error detected: Value '1000' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 60"
    )
    assert message_over == expected_over, (
        f"expected message {expected_over!r}, got {message_over!r}"
    )

    control_raw = raw.list_identities(IdentityPoolId=pool_id, MaxResults=1)
    assert "Identities" in control_raw, f"expected a successful response to carry Identities, got {control_raw!r}"


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
