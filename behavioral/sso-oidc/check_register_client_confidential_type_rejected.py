"""register-client-confidential-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-client-confidential-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterClient with clientType confidential is InvalidClientMetadataException "Invalid client type
    provided", while clientType public returns a clientId and clientSecret whose client reaches
    CreateToken's grant lookup (InvalidGrantException "Invalid device code provided")."""
    sso_oidc = ctx.client("sso-oidc")
    name = ctx.unique_name("sim2real-ssooidc-client-")

    try:
        sso_oidc.register_client(clientName=name, clientType="confidential")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidClientMetadataException", (
            f"expected InvalidClientMetadataException, got "
            f"{err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid client type provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError(
            "expected InvalidClientMetadataException for clientType=confidential"
        )

    # Effect absent: no client-register side effect should carry over from
    # the rejected call -- a fresh public registration under the same name
    # still mints its own independent credential pair.
    control = sso_oidc.register_client(clientName=name, clientType="public")
    assert control["clientId"], "clientId must be non-empty"
    assert control["clientSecret"], "clientSecret must be non-empty"

    # Independent read at the destination: prove the public registration is genuinely usable, not
    # just that RegisterClient echoed non-empty fields. CreateToken's entitlement check runs
    # regardless of this account having no active IAM Identity Center instance, so a fabricated
    # device code reaching grant-lookup (InvalidGrantException) rather than being turned away at the
    # entitlement layer (UnauthorizedClientException) proves the credential pair the rejected
    # confidential call left behind actually works.
    try:
        sso_oidc.create_token(
            clientId=control["clientId"],
            clientSecret=control["clientSecret"],
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode="sim2real-fabricated-device-code-does-not-exist",
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidGrantException", (
            f"expected InvalidGrantException (proving the client is "
            f"entitled), got {err.response['Error']['Code']!r}"
        )
        assert err.response["Error"]["Message"] == "Invalid device code provided", (
            f"unexpected message: {err.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError("expected InvalidGrantException")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
