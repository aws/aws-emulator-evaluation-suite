"""create-token-invalid-grant-unknown-device-code-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-token-invalid-grant-unknown-device-code-rejected"
GROUP = "error-semantics"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateToken with a device_code grant whose deviceCode was never issued is rejected with
    InvalidGrantException "Invalid device code provided", for a client RegisterClient just returned
    with a non-empty clientId and clientSecret."""
    sso_oidc = ctx.client("sso-oidc")
    client = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
        grantTypes=["urn:ietf:params:oauth:grant-type:device_code"],
    )
    assert client["clientId"] and client["clientSecret"], (
        "positive control: RegisterClient did not return usable credentials"
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
            f"expected InvalidGrantException, got "
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
