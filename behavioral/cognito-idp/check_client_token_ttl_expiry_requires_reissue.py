"""client-token-ttl-expiry-requires-reissue."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "client-token-ttl-expiry-requires-reissue"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-idp"]


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With AccessTokenValidity at its 5-minute minimum, GetClientToken returns ExpiresIn 300, and
    after that token's exp passes a new call returns a different token with a later exp."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)

    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-m2m-"),
        GenerateSecret=True,
        ExplicitAuthFlows=["ALLOW_CLIENT_TOKEN_AUTH"],
        AccessTokenValidity=300,
        TokenValidityUnits={"AccessToken": "seconds"},
    )["UserPoolClient"]
    client_id = client["ClientId"]
    client_secret = client["ClientSecret"]

    first = cognito.get_client_token(ClientId=client_id, Secret=client_secret)
    car1 = first["ClientAuthenticationResult"]
    token1 = car1["AccessToken"]
    assert car1["ExpiresIn"] == 300, f"expected a 300-second TTL, got {car1['ExpiresIn']}"

    claims1 = _decode_jwt_payload(token1)
    exp1 = claims1["exp"]

    def _probe():
        return time.time()

    _poll_until(_probe, lambda now: now > exp1 + 5, timeout_s=420.0, interval_s=10.0)

    second = cognito.get_client_token(ClientId=client_id, Secret=client_secret)
    car2 = second["ClientAuthenticationResult"]
    token2 = car2["AccessToken"]
    assert token2 != token1, "reissue after TTL expiry returned the exact same (now-stale) token"

    claims2 = _decode_jwt_payload(token2)
    assert claims2["exp"] > exp1, "freshly reissued token's expiry is not later than the elapsed token's expiry"
    assert claims2["iat"] >= claims1["iat"], "freshly reissued token was not minted after the original"


def _create_user_pool(ctx, cognito, **overrides):
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    pool_id = cognito.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _decode_jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64 + padding))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
