"""create-token-with-iam-unsupported-grant-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-token-with-iam-unsupported-grant-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTokenWithIAM with grantType device_code is InvalidClientException "Invalid client
    provided", while the same bogus application ARN with a refresh_token grant gets
    InvalidGrantException "Invalid refresh token provided"; RegisterClient returns a clientId."""
    sso_oidc = ctx.client("sso-oidc")
    bogus_arn = (
        "arn:aws:sso::111122223333:application/ssoins-0000000000000000/"
        "apl-0000000000000000"
    )

    try:
        sso_oidc.create_token_with_iam(
            clientId=bogus_arn,
            grantType="urn:ietf:params:oauth:grant-type:device_code",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidClientException", (
            f"expected InvalidClientException, got "
            f"{err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid client provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError("expected InvalidClientException")

    # Contrast: the SAME bogus ARN under a supported grant type reaches
    # grant-lookup instead of being turned away as an unusable grant shape.
    try:
        sso_oidc.create_token_with_iam(
            clientId=bogus_arn,
            grantType="refresh_token",
            refreshToken="sim2real-bogus-refresh-token",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidGrantException", (
            f"expected InvalidGrantException for the supported-grant "
            f"contrast, got {err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid refresh token provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError("expected InvalidGrantException")

    # Positive control (general credential plumbing, see docstring above).
    control = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
    )
    assert control["clientId"], "expected RegisterClient to return a clientId"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
