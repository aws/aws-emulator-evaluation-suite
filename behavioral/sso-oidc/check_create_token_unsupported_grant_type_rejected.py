"""create-token-unsupported-grant-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-token-unsupported-grant-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateToken with grantType client_credentials is InvalidRequestException "Invalid request", while
    a device_code grant from the same client clears grant-type validation and gets
    InvalidGrantException "Invalid device code provided"."""
    sso_oidc = ctx.client("sso-oidc")
    client = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
    )

    try:
        sso_oidc.create_token(
            clientId=client["clientId"],
            clientSecret=client["clientSecret"],
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode="sim2real-fabricated-device-code-does-not-exist",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidGrantException", (
            f"positive control: a supported grant type with an unknown "
            f"code should reach grant-lookup (InvalidGrantException), got "
            f"{err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid device code provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError(
            "positive control: expected InvalidGrantException for a "
            "supported grant type with a fabricated device code"
        )

    try:
        sso_oidc.create_token(
            clientId=client["clientId"],
            clientSecret=client["clientSecret"],
            grantType="client_credentials",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidRequestException", (
            f"expected InvalidRequestException, got "
            f"{err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid request", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError("expected InvalidRequestException for client_credentials")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
