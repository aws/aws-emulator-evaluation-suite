"""create-token-refresh-token-invalid-grant-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-token-refresh-token-invalid-grant-rejected"
GROUP = "error-semantics"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateToken with grantType refresh_token and no refreshToken is InvalidRequestException "Refresh
    token is required", while a present but never-issued refreshToken is InvalidGrantException
    "Invalid refresh token provided"."""
    sso_oidc = ctx.client("sso-oidc")
    client = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
    )

    try:
        sso_oidc.create_token(
            clientId=client["clientId"],
            clientSecret=client["clientSecret"],
            grantType="refresh_token",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidRequestException", (
            f"expected InvalidRequestException for missing refreshToken, "
            f"got {err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Refresh token is required", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError(
            "expected InvalidRequestException for missing refreshToken"
        )

    try:
        sso_oidc.create_token(
            clientId=client["clientId"],
            clientSecret=client["clientSecret"],
            grantType="refresh_token",
            refreshToken="sim2real-bogus-refresh-token-value",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidGrantException", (
            f"expected InvalidGrantException for a bogus refreshToken, got "
            f"{err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid refresh token provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
        return
    raise AssertionError("expected InvalidGrantException for a bogus refreshToken")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
