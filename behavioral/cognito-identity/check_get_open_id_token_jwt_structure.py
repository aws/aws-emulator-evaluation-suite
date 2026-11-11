"""get-open-id-token-jwt-structure."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-jwt-structure"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


def _decode_jwt(token: str) -> tuple[dict, dict]:
    """(header, payload) of a JWS, or raises if it is not a well-formed 3-segment token."""
    parts = token.split(".")
    assert len(parts) == 3, f"expected a 3-part JWT, got {len(parts)} parts"
    assert parts[2], "signature segment must be non-empty"

    def _b64url_json(segment: str) -> dict:
        padding = "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(segment + padding))

    return _b64url_json(parts[0]), _b64url_json(parts[1])


def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetOpenIdToken returns a three-part JWT whose sub, aud and amr claims name the identity, the
    pool and the unauthenticated flow, and STS AssumeRoleWithWebIdentity redeems it for a session of
    the pool's role."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    resp = ci.get_open_id_token(IdentityId=identity_id)
    assert resp["IdentityId"] == identity_id
    token = resp["Token"]

    header, claims = _decode_jwt(token)
    assert isinstance(header.get("alg"), str) and header["alg"], (
        f"JWT header must carry a non-empty alg, got {header.get('alg')!r}"
    )
    assert claims["sub"] == identity_id, f"sub claim {claims.get('sub')} != identity id {identity_id}"
    assert claims["aud"] == pool_id, f"aud claim {claims.get('aud')} != pool id {pool_id}"
    assert "cognito-identity" in claims["iss"], f"unexpected iss claim: {claims.get('iss')}"
    assert claims["exp"] > 0
    assert "unauthenticated" in claims.get("amr", []), (
        f"a guest identity's token must carry amr=unauthenticated, got {claims.get('amr')!r}"
    )

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}},
                }
            ],
        }
    )
    role_name = ctx.unique_name("sim2real-behav-jwt-structure-")[:64]
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = "sim2real-behav-jwt-structure"
    assumed = _poll_until(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=role_arn, RoleSessionName=session_name, WebIdentityToken=token
        ),
        lambda r: "Credentials" in r,
        description="sts:AssumeRoleWithWebIdentity to accept the minted token (role propagation)",
    )
    creds = assumed["Credentials"]
    assert creds["AccessKeyId"] and creds["SecretAccessKey"] and creds["SessionToken"], (
        f"incomplete credential envelope: {sorted(creds)}"
    )
    assert assumed["SubjectFromWebIdentityToken"] == identity_id, (
        f"SubjectFromWebIdentityToken must be the IdentityId {identity_id}, got "
        f"{assumed['SubjectFromWebIdentityToken']!r}"
    )

    federated_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    caller_arn = _poll_until(
        lambda: federated_sts.get_caller_identity(),
        lambda r: "Arn" in r,
        timeout_s=30.0,
        interval_s=2.0,
        description="freshly-assumed web-identity session to become usable for GetCallerIdentity",
    )["Arn"]
    assert f":assumed-role/{role_name}/" in caller_arn, (
        f"the redeemed credentials must actually work and name {role_name}, got {caller_arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
