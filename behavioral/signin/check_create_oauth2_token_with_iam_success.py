"""create-oauth2-token-with-iam-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-oauth2-token-with-iam-success"
GROUP = "oauth2-token"
SERVICES = ["signin"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOAuth2TokenWithIAM (client_credentials, SigV4) mints a Bearer token with expiresIn within 1-3600 s,
    and IntrospectOAuth2TokenWithIAM reports it active with tokenType access_token.
    """
    signin = ctx.client("signin")
    resp = signin.create_oauth2_token_with_iam(
        grantType="client_credentials",
        resource="aws-mcp.amazonaws.com",
    )
    assert resp["tokenType"] == "Bearer", f"expected Bearer, got {resp['tokenType']!r}"
    assert 1 <= resp["expiresIn"] <= 3600, (
        f"expiresIn {resp['expiresIn']!r} outside the documented 1-3600s window"
    )
    access_token = resp["accessToken"]
    assert isinstance(access_token, str) and 1 <= len(access_token) <= 4096, (
        f"accessToken not a 1-4096 char string: {access_token!r}"
    )

    # terminal read: a different operation confirms the minted token is real and usable, not
    # just shaped correctly.
    introspected = signin.introspect_oauth2_token_with_iam(
        token=access_token, tokenTypeHint="access_token"
    )
    assert introspected["active"] is True, f"expected active token, got {introspected}"
    assert introspected["tokenType"] == "access_token", (
        f"expected tokenType access_token, got {introspected['tokenType']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
