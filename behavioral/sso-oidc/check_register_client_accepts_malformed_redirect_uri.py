"""register-client-accepts-malformed-redirect-uri."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-client-accepts-malformed-redirect-uri"
GROUP = "state"
SERVICES = ["sso-oidc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterClient accepts a malformed redirectUris entry and returns a clientId and clientSecret, and
    that client reaches CreateToken's grant lookup: InvalidGrantException "Invalid device code
    provided" for a fabricated device code. AWS defers redirect URI checks to the redirect itself."""
    sso_oidc = ctx.client("sso-oidc")

    resp = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
        redirectUris=["not_a_valid_uri this is definitely malformed"],
    )
    assert resp["clientId"], "RegisterClient must return a non-empty clientId"
    assert resp["clientSecret"], (
        "RegisterClient must return a non-empty clientSecret"
    )

    try:
        sso_oidc.create_token(
            clientId=resp["clientId"],
            clientSecret=resp["clientSecret"],
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode="sim2real-fabricated-device-code-does-not-exist",
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "InvalidGrantException", (
            f"client registered with a malformed redirectUris entry should "
            f"still be a fully usable, entitled default client (expected "
            f"InvalidGrantException for the fabricated device code), got "
            f"{code!r}"
        )
        message = err.response["Error"]["Message"]
        assert message == "Invalid device code provided", (
            f"unexpected message: {message!r}"
        )
    else:
        raise AssertionError(
            "expected InvalidGrantException for a fabricated device code"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
