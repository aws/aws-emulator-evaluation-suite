"""create-token-with-iam-invalid-client-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-token-with-iam-invalid-client-rejected"
GROUP = "error-semantics"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTokenWithIAM with a well-formed but nonexistent application ARN and a fabricated
    refreshToken is InvalidGrantException "Invalid refresh token provided"; a client from
    RegisterClient reaches CreateToken's grant lookup (InvalidGrantException "Invalid device code provided")."""
    sso_oidc = ctx.client("sso-oidc")

    bogus_arn = (
        "arn:aws:sso::111122223333:application/ssoins-0000000000000000/"
        "apl-0000000000000000"
    )
    try:
        sso_oidc.create_token_with_iam(
            clientId=bogus_arn,
            grantType="refresh_token",
            refreshToken="sim2real-bogus-refresh-token",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidGrantException", (
            f"expected InvalidGrantException, got "
            f"{err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid refresh token provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError("expected InvalidGrantException")

    # Positive control (general credential plumbing, see docstring above): register a
    # real client, then -- through an INDEPENDENT operation, not RegisterClient's own
    # response -- prove those credentials are live by driving them into the same
    # token-issuance surface far enough to reach grant-lookup (InvalidGrantException on
    # a fabricated device code), not rejected earlier as an unrecognized/unauthorized
    # client. This is what rules out an emulator that blanket-rejects
    # CreateTokenWithIAM while leaving RegisterClient itself untouched.
    control = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
    )
    assert control["clientId"], f"RegisterClient returned no clientId: {control!r}"

    try:
        sso_oidc.create_token(
            clientId=control["clientId"],
            clientSecret=control["clientSecret"],
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode="sim2real-bogus-device-code",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidGrantException", (
            f"freshly registered client credentials should reach grant-lookup "
            f"(InvalidGrantException) on a fabricated device code, got "
            f"{err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid device code provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError(
            "expected InvalidGrantException for a fabricated device code"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
