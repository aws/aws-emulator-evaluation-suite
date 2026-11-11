"""start-verification-invalid-country-code-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-verification-invalid-country-code-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is only served from us-east-1; ctx.client()'s default region
    (us-west-2) has no endpoint for it. ctx.client()'s `region=` override pins the region for
    this client only while keeping the caller's credentials and endpoint/TLS wiring, so
    this needs no reach into Context's private attributes. On an emulator all services share one
    endpoint regardless of region, so the same call is correct there too."""
    return ctx.client("partnercentral-account", region="us-east-1")


def _error(fn):
    """Call fn(); return its botocore error code, message and request id. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return (
            e.response["Error"]["Code"],
            e.response["Error"]["Message"],
            e.response["ResponseMetadata"]["RequestId"],
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartVerification with a BusinessVerificationDetails.CountryCode that is not a 2-letter ISO code fails
    with ValidationException, GetVerification still reports no BUSINESS_VERIFICATION started, and an unrelated
    account-level call succeeds.
    """
    pca = _pca_client(ctx)

    # Positive control: unrelated account-level call succeeds.
    pca.get_connection_preferences(Catalog="AWS")

    code, message, _ = _error(
        lambda: pca.start_verification(
            VerificationDetails={
                "BusinessVerificationDetails": {
                    "LegalName": "Sim2Real Behavioral Fidelity Co",
                    "RegistrationId": "SIM2REAL-0001",
                    "CountryCode": "USA",  # invalid: must be exactly 2 letters (ISO 3166-1 alpha-2)
                }
            }
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a 3-letter CountryCode, got {code!r}"
    field = "verificationDetails.businessVerificationDetails.countryCode"
    assert message == (
        f"2 validation errors detected: Value at '{field}' failed to satisfy constraint: Member "
        f"must have length less than or equal to 2; Value at '{field}' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [A-Z]{2}"
    ), message

    # Effect absent: the rejected call never started a verification.
    not_found_code, not_found_message, request_id = _error(
        lambda: pca.get_verification(VerificationType="BUSINESS_VERIFICATION")
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException (no verification ever started), got {not_found_code!r}"
    )
    # The message names the failing call's own request id, as its response metadata reports it.
    assert not_found_message == (
        f"Verification not found for requestId: {request_id}, accountId: {ctx.account} and "
        "verificationType: BUSINESS_VERIFICATION"
    ), not_found_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
