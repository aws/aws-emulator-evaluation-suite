"""register-client-default-grant-types-allow-device-flow."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-client-default-grant-types-allow-device-flow"
GROUP = "state"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A client registered without grantTypes is not turned away for the device_code grant: CreateToken
    with a fabricated device code answers InvalidGrantException "Invalid device code provided", not
    UnauthorizedClientException."""
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
            f"default-registered client should be entitled to device_code "
            f"(InvalidGrantException for the unknown code), got "
            f"{err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid device code provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
        return
    raise AssertionError("expected InvalidGrantException")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
