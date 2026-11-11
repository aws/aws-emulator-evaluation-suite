"""introspect-oauth2-token-with-iam-hint-optional."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "introspect-oauth2-token-with-iam-hint-optional"
GROUP = "oauth2-token"
SERVICES = ["signin"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """IntrospectOAuth2TokenWithIAM reports a valid access token active with tokenType access_token both without
    tokenTypeHint and with the wrong hint (refresh_token), as the model documents the hint as a lookup
    optimization only.
    """
    signin = ctx.client("signin")
    created = signin.create_oauth2_token_with_iam(
        grantType="client_credentials",
        resource="aws-mcp.amazonaws.com",
    )
    access_token = created["accessToken"]

    no_hint = signin.introspect_oauth2_token_with_iam(token=access_token)
    assert no_hint["active"] is True, f"expected active=True with no hint, got {no_hint['active']!r}"
    assert no_hint["tokenType"] == "access_token", (
        f"expected tokenType=access_token with no hint, got {no_hint['tokenType']!r}"
    )

    wrong_hint = signin.introspect_oauth2_token_with_iam(
        token=access_token, tokenTypeHint="refresh_token"
    )
    assert wrong_hint["active"] is True, (
        f"expected active=True despite a mismatched refresh_token hint on an access "
        f"token, got {wrong_hint['active']!r}"
    )
    assert wrong_hint["tokenType"] == "access_token", (
        f"expected tokenType=access_token despite a mismatched hint, got {wrong_hint['tokenType']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
