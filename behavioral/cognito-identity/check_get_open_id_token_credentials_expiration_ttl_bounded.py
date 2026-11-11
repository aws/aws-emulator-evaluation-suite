"""get-open-id-token-credentials-expiration-ttl-bounded."""
from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-credentials-expiration-ttl-bounded"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetOpenIdToken issues a JWT whose iat is the call time and whose exp-iat lies in 300-960 s,
    and GetCredentialsForIdentity returns an Expiration between 60 s and 65 min in the future."""
    cognito = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = _create_pool(ctx)
    identity_id = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: cognito.delete_identities(IdentityIdsToDelete=[identity_id]))

    before = time.time()
    token = cognito.get_open_id_token(IdentityId=identity_id)["Token"]
    after = time.time()

    payload = _decode_jwt_payload(token)
    assert "exp" in payload, "OpenID token JWT is missing an exp claim"
    exp = float(payload["exp"])
    assert "iat" in payload, "OpenID token JWT is missing an iat claim"
    iat = float(payload["iat"])

    # Documented contract: "The OpenID token is valid for 10 minutes." Bound the
    # window generously (5-16 minutes) to absorb clock skew, never unbounded.
    ttl = exp - iat
    assert 300 <= ttl <= 960, f"OpenID token TTL {ttl}s is not ~10 minutes as documented"
    assert before - 5 <= iat <= after + 5, f"OpenID token iat {iat} not around issuance time (now={after})"

    # Wire up a trusted role so GetCredentialsForIdentity can actually issue credentials.
    role_arn = _create_cognito_role(ctx, iam, pool_id)
    cognito.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    creds = _poll_until(
        lambda: _try_get_credentials(cognito, identity_id),
        lambda c: c is not None,
        timeout_s=90, interval_s=5,
    )
    expiration = creds["Expiration"]
    exp_ts = expiration.timestamp() if hasattr(expiration, "timestamp") else float(expiration)
    now = time.time()
    assert exp_ts > now, f"credentials Expiration {exp_ts} is already in the past (now={now})"
    # STS temporary credentials issued through the enhanced flow default to a bounded
    # session (commonly up to 1 hour); assert a sane bounded ceiling, never missing/unbounded.
    assert exp_ts <= now + 3900, f"credentials Expiration {exp_ts} exceeds a bounded TTL window (now={now})"
    assert exp_ts >= now + 60, f"credentials Expiration {exp_ts} implausibly close to issuance (now={now})"


def _create_pool(ctx, allow_unauth: bool = True) -> str:
    cognito = ctx.client("cognito-identity")
    resp = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool"),
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real-behav-check": CHECK},
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_cognito_role(ctx, iam, pool_id: str, amr: str = "unauthenticated") -> str:
    name = ctx.unique_name("sim2real-behav-cirole")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
            },
        }],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        raise AssertionError(f"OpenID token is not a well-formed JWT: {token!r}")
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
    return json.loads(payload_bytes)


def _try_get_credentials(cognito, identity_id: str):
    try:
        return cognito.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
    except ClientError:
        return None


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 1.0,
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
