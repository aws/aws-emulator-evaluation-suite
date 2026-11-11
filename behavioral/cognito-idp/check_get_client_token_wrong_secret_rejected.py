"""get-client-token-wrong-secret-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-client-token-wrong-secret-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetClientToken returns an access token for the real client secret, fails with
    NotAuthorizedException and its exact message for a corrupted one, and still works with the real
    secret afterwards."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)

    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-m2m-"),
        GenerateSecret=True,
        ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
    )["UserPoolClient"]
    client_id = client["ClientId"]
    client_secret = client["ClientSecret"]

    good = cognito.get_client_token(ClientId=client_id, Secret=client_secret)
    assert "AccessToken" in good["ClientAuthenticationResult"], (
        f"expected AccessToken in response, got {good['ClientAuthenticationResult']!r}"
    )

    wrong_secret = client_secret[:-1] + ("0" if client_secret[-1] != "0" else "1")
    code = _error(lambda: cognito.get_client_token(ClientId=client_id, Secret=wrong_secret))
    assert code == ("NotAuthorizedException", "Invalid client or secret"), (
        f"expected NotAuthorizedException, got {code!r}"
    )

    # positive control still works after the rejected attempt
    good2 = cognito.get_client_token(ClientId=client_id, Secret=client_secret)
    assert "AccessToken" in good2["ClientAuthenticationResult"], (
        f"expected AccessToken in response after restore, got {good2['ClientAuthenticationResult']!r}"
    )


def _create_user_pool(ctx, cognito, **overrides):
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "DeletionProtection": "INACTIVE",
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    pool_id = cognito.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, so an
    emulator accepting a call real AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
