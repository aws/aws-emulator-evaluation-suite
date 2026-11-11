"""create-oauth2-token-with-iam-rotates-access-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-oauth2-token-with-iam-rotates-access-token"
GROUP = "oauth2-token"
SERVICES = ["signin"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two CreateOAuth2TokenWithIAM calls for the same resource mint distinct Bearer access tokens, and
    IntrospectOAuth2TokenWithIAM reports each of them active, so each call issues a separately live grant.
    """
    signin = ctx.client("signin")
    resource = "aws-mcp.amazonaws.com"
    first = signin.create_oauth2_token_with_iam(grantType="client_credentials", resource=resource)
    second = signin.create_oauth2_token_with_iam(grantType="client_credentials", resource=resource)

    assert first["accessToken"] != second["accessToken"], (
        f"expected two distinct access tokens for repeated calls with identical "
        f"(grantType, resource); got the same token twice: {first['accessToken']!r}"
    )
    assert first["tokenType"] == second["tokenType"] == "Bearer", (
        f"expected tokenType Bearer on both calls, got {first['tokenType']!r} "
        f"and {second['tokenType']!r}"
    )

    def introspect(token):
        return signin.introspect_oauth2_token_with_iam(token=token, tokenTypeHint="access_token")

    first_introspected = introspect(first["accessToken"])
    second_introspected = introspect(second["accessToken"])
    assert first_introspected["active"] is True, (
        f"expected freshly-minted first token to introspect active, got {first_introspected}"
    )
    assert second_introspected["active"] is True, (
        f"expected freshly-minted second token to introspect active, got {second_introspected}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
