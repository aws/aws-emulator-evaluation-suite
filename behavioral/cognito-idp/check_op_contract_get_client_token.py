"""op-contract-get-client-token."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-get-client-token"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetClientToken issues an M2M access token for an app client configured with
    ALLOW_CLIENT_TOKEN_AUTH and a matching secret, and rejects the same client id when
    presented with the wrong secret."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    try:
        client = idp.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=ctx.unique_name("sim2real-behav-m2m-"),
            GenerateSecret=True,
            ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
        )["UserPoolClient"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidParameterException":
            raise AssertionError("ALLOW_CLIENT_TOKEN_AUTH (M2M client credentials) not available here")
        raise
    client_id = client["ClientId"]
    client_secret = client["ClientSecret"]

    # success path: the correct client id + secret yields a bearer access token
    resp = idp.get_client_token(ClientId=client_id, Secret=client_secret)
    result = resp["ClientAuthenticationResult"]
    assert result["AccessToken"], "expected a non-empty AccessToken"
    assert result["TokenType"] == "Bearer", f"expected token_type Bearer, got {result['TokenType']!r}"
    assert result["ExpiresIn"] > 0, f"expected a positive ExpiresIn, got {result['ExpiresIn']!r}"

    # distinct error boundary: the same client id with a wrong (but well-formed) secret
    # is rejected as NotAuthorizedException, not silently issued a token
    wrong_secret = ("x" * 24) if client_secret[0] != "x" else ("y" * 24)
    code = _error(lambda: idp.get_client_token(ClientId=client_id, Secret=wrong_secret))
    assert code == ("NotAuthorizedException", "Invalid client or secret"), (
        f"expected NotAuthorizedException, got {code!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Code, Message); an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
