"""introspect-oauth2-token-with-iam-resource-claim-round-trip-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "introspect-oauth2-token-with-iam-resource-claim-round-trip-preserved"
GROUP = "oauth2-token"
SERVICES = ["signin"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """IntrospectOAuth2TokenWithIAM on a minted access token reports active, tokenType access_token, aud equal
    to the exact resource string sent, the caller's account id, and exp - iat within 5 s of expiresIn.
    """
    signin = ctx.client("signin")
    resource = "aws-mcp.amazonaws.com"
    created = signin.create_oauth2_token_with_iam(
        grantType="client_credentials",
        resource=resource,
    )
    account_id = _account_id(ctx)

    introspected = signin.introspect_oauth2_token_with_iam(
        token=created["accessToken"], tokenTypeHint="access_token"
    )

    assert introspected["active"] is True, f"expected active=True, got {introspected['active']!r}"
    assert introspected["tokenType"] == "access_token", (
        f"expected tokenType='access_token', got {introspected['tokenType']!r}"
    )
    # round-trip: the exact resource string we sent comes back unchanged in `aud`.
    assert introspected["aud"] == resource, (
        f"expected aud={resource!r} (round-tripped from create's resource), got {introspected['aud']!r}"
    )
    assert introspected["accountId"] == account_id, (
        f"expected accountId={account_id!r} (caller's own account), got {introspected['accountId']!r}"
    )
    assert introspected["exp"] > introspected["iat"], (
        f"expected exp > iat, got exp={introspected['exp']!r} iat={introspected['iat']!r}"
    )
    lifetime = introspected["exp"] - introspected["iat"]
    # allow a small slack around the create call's declared expiresIn
    assert abs(lifetime - created["expiresIn"]) <= 5, (
        f"expected lifetime (exp-iat)={lifetime} within 5s of create's expiresIn={created['expiresIn']}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
