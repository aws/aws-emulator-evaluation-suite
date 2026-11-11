"""introspect-oauth2-token-with-iam-malformed-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "introspect-oauth2-token-with-iam-malformed-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["signin"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IntrospectOAuth2TokenWithIAM rejects a token outside the documented ^ASO[AR] shape with
    ValidationException "token has invalid format" rather than answering active=false, while a freshly minted
    access token introspects as active.
    """
    signin = ctx.client("signin")

    code, message = _error(
        lambda: signin.introspect_oauth2_token_with_iam(token="not-a-signin-token-at-all")
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a token not shaped like ASO[AR]..., got {code!r}"
    )
    assert message == "token has invalid format", (
        f"expected message 'token has invalid format' for a token not shaped like ASO[AR]..., got {message!r}"
    )

    # positive control: a real, correctly-shaped access token is accepted and active
    created = signin.create_oauth2_token_with_iam(
        grantType="client_credentials", resource="aws-mcp.amazonaws.com"
    )
    introspected = signin.introspect_oauth2_token_with_iam(token=created["accessToken"])
    assert introspected["active"] is True, (
        f"expected a freshly minted, correctly-shaped access token to introspect as active, "
        f"got active={introspected.get('active')!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
