"""create-token-refresh-token-lookup-precedes-client-existence."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-token-refresh-token-lookup-precedes-client-existence"
GROUP = "error-semantics"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateToken with a never-registered clientId and a fabricated refreshToken answers
    InvalidGrantException "Invalid refresh token provided", not InvalidClientException: the token is
    checked before the client; RegisterClient returning a clientId confirms the service answers."""
    sso_oidc = ctx.client("sso-oidc")

    try:
        sso_oidc.create_token(
            clientId=ctx.unique_name("sim2real-never-registered-"),
            clientSecret="totally-bogus-secret-value",
            grantType="refresh_token",
            refreshToken="sim2real-bogus-refresh-token-value",
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

    # Positive control (general credential plumbing, see docstring above).
    control = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
    )
    assert control["clientId"], "expected register_client to return a clientId"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
