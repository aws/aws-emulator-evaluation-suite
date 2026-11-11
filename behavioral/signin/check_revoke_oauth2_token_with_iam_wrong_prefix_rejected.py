"""revoke-oauth2-token-with-iam-wrong-prefix-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoke-oauth2-token-with-iam-wrong-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["signin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an empty token RevokeOAuth2TokenWithIAM answers a no-op 200 while IntrospectOAuth2TokenWithIAM rejects
    it with ValidationException "token is required"; revoking an access-token-shaped (ASOA) value is a no-op
    that leaves that token active.
    """
    signin = ctx.client("signin")
    unvalidated_signin = ctx.client("signin", config=Config(parameter_validation=False))

    # empty-token boundary: botocore's parameter validator enforces minLength=1 locally on both
    # operations, so an unvalidated client sends the empty token to the service itself.
    unvalidated_signin.revoke_oauth2_token_with_iam(token="")  # must not raise (idempotent-safe no-op)
    error = _client_error(
        lambda: unvalidated_signin.introspect_oauth2_token_with_iam(
            token="", tokenTypeHint="refresh_token"
        )
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException introspecting an empty token, got {error!r}"
    )
    assert error.get("Message") == "token is required", (
        f"expected message 'token is required' introspecting an empty token, got {error!r}"
    )

    # type-mismatch boundary: an access token (ASOA) is not a revocation-shaped
    # (ASOR) token. The call must not silently revoke it as a side effect of the
    # idempotent-safe no-op path.
    created = signin.create_oauth2_token_with_iam(
        grantType="client_credentials",
        resource="aws-mcp.amazonaws.com",
    )
    access_token = created["accessToken"]
    signin.revoke_oauth2_token_with_iam(token=access_token)  # must not raise (idempotent-safe no-op)

    introspected = signin.introspect_oauth2_token_with_iam(
        token=access_token, tokenTypeHint="access_token"
    )
    assert introspected["active"] is True, (
        "revoking an access-token-shaped value must be a no-op, not an actual revocation"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    that accepts input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
