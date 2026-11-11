"""create-token-missing-device-code-invalid-request-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-token-missing-device-code-invalid-request-rejected"
GROUP = "error-semantics"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateToken with grantType device_code and no deviceCode is InvalidRequestException "Device code
    is required", while the same client with a fabricated deviceCode gets InvalidGrantException
    "Invalid device code provided": the first refusal is specific to the missing member."""
    sso_oidc = ctx.client("sso-oidc")
    client = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
        grantTypes=["urn:ietf:params:oauth:grant-type:device_code"],
    )

    try:
        sso_oidc.create_token(
            clientId=client["clientId"],
            clientSecret=client["clientSecret"],
            grantType="urn:ietf:params:oauth:grant-type:device_code",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidRequestException", (
            f"expected InvalidRequestException, got "
            f"{err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Device code is required", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError("expected InvalidRequestException")

    try:
        sso_oidc.create_token(
            clientId=client["clientId"],
            clientSecret=client["clientSecret"],
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode="sim2real-fabricated-device-code-does-not-exist",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidGrantException", (
            f"expected InvalidGrantException once deviceCode is present, "
            f"got {err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid device code provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError("expected InvalidGrantException")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
