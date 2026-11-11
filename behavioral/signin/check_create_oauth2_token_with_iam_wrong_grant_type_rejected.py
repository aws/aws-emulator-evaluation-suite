"""create-oauth2-token-with-iam-wrong-grant-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-oauth2-token-with-iam-wrong-grant-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["signin"]

INVALID_REQUEST_MESSAGE = (
    "The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed."
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOAuth2TokenWithIAM only implements the client_credentials grant;
    any other grantType value is rejected with ValidationException, and a
    correctly-shaped request right after still succeeds (positive control)."""
    signin = ctx.client("signin")

    code, message = _error(
        lambda: signin.create_oauth2_token_with_iam(
            grantType="authorization_code",
            resource="aws-mcp.amazonaws.com",
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for grantType=authorization_code, got {code!r}"
    )
    assert message == INVALID_REQUEST_MESSAGE, (
        f"expected message {INVALID_REQUEST_MESSAGE!r} for grantType=authorization_code, got {message!r}"
    )

    # positive control: a syntactically valid client_credentials request succeeds
    resp = signin.create_oauth2_token_with_iam(
        grantType="client_credentials",
        resource="aws-mcp.amazonaws.com",
    )
    assert resp["tokenType"] == "Bearer", f"expected tokenType Bearer, got {resp['tokenType']!r}"
    assert isinstance(resp["accessToken"], str) and len(resp["accessToken"]) > 0, (
        f"expected a non-empty string accessToken, got {resp['accessToken']!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING a grantType real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects grantType=authorization_code, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
