"""classic-flow-open-id-token-assume-role-with-web-identity."""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "classic-flow-open-id-token-assume-role-with-web-identity"
GROUP = 'credentials'
SERVICES = ['cognito-identity']

# The federated principal the trust policies name; STS reports it back as the token Provider.
COGNITO_PRINCIPAL = "cognito-identity.amazonaws.com"



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


def _decode_jwt_claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _create_identity_pool(ci, ctx, allow_unauth=True, **kwargs):
    name = ctx.unique_name("sim2real-behav-cip-").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _cognito_trust_policy(pool_id, amr=None):
    condition = {"StringEquals": {f"{COGNITO_PRINCIPAL}:aud": pool_id}}
    if amr:
        condition["ForAnyValue:StringLike"] = {f"{COGNITO_PRINCIPAL}:amr": amr}
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": COGNITO_PRINCIPAL},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": condition,
        }],
    })


def _create_role(iam, ctx, trust_policy, label):
    name = ctx.unique_name(f"sim2real-behav-{label}-")[:64]
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


def _client_from_credentials(ctx, service, creds):
    """A client on the target signed with the vended temporary credentials, never os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _error(fn):
    """Call fn() expecting failure; return the AWS error (code, message). An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be denied, but it SUCCEEDED and returned {result!r}")



@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOpenIdToken mints a token (sub = IdentityId, aud = pool) that AssumeRoleWithWebIdentity
    redeems, and STS denies it for a role trusting a different pool's aud; a 2x2 pool/role
    matrix separates the aud denial from IAM propagation lag."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    pool_a = _create_identity_pool(ci, ctx, allow_unauth=True, AllowClassicFlow=True)
    pool_b = _create_identity_pool(ci, ctx, allow_unauth=True, AllowClassicFlow=True)

    described = ci.describe_identity_pool(IdentityPoolId=pool_a)
    assert described.get("AllowClassicFlow") is True, (
        f"DescribeIdentityPool must echo AllowClassicFlow=True, got "
        f"{described.get('AllowClassicFlow')!r}"
    )

    role_a_name, role_a_arn = _create_role(iam, ctx, _cognito_trust_policy(pool_a), "classic-a")
    role_b_name, role_b_arn = _create_role(iam, ctx, _cognito_trust_policy(pool_b), "classic-b")

    def _open_id_token(pool_id):
        identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
        response = ci.get_open_id_token(IdentityId=identity_id)
        assert response["IdentityId"] == identity_id, (
            f"GetOpenIdToken echoed IdentityId {response['IdentityId']} != {identity_id}"
        )
        return identity_id, response["Token"]

    identity_a, token_a = _open_id_token(pool_a)
    identity_b, token_b = _open_id_token(pool_b)

    claims = _decode_jwt_claims(token_a)
    assert claims.get("sub") == identity_a, (
        f"the OpenID token's sub must be the IdentityId {identity_a}, got {claims.get('sub')!r}"
    )
    assert claims.get("aud") == pool_a, (
        f"the OpenID token's aud must be the identity pool {pool_a}, got {claims.get('aud')!r}"
    )
    assert "unauthenticated" in claims.get("amr", []), (
        f"a guest identity's token must carry amr=unauthenticated, got {claims.get('amr')!r}"
    )

    session_name = "sim2real-behav-classic"

    def _assume(role_arn, token):
        return sts.assume_role_with_web_identity(
            RoleArn=role_arn, RoleSessionName=session_name, WebIdentityToken=token,
        )

    assumed = _poll_until(
        lambda: _assume(role_a_arn, token_a),
        lambda r: "Credentials" in r,
        timeout_s=180.0,
        description="sts:AssumeRoleWithWebIdentity to accept the pool A token (role propagation)",
    )
    creds = assumed["Credentials"]
    assert creds["AccessKeyId"].startswith("ASIA"), (
        f"STS session key must start with ASIA, got {creds['AccessKeyId']}"
    )
    assert creds["SecretAccessKey"] and creds["SessionToken"], (
        f"incomplete credential envelope: {sorted(creds)}"
    )
    assert creds["Expiration"] > datetime.now(timezone.utc), (
        f"credential Expiration {creds['Expiration']} is not in the future"
    )
    assert assumed["SubjectFromWebIdentityToken"] == identity_a, (
        f"SubjectFromWebIdentityToken must be the IdentityId {identity_a}, got "
        f"{assumed['SubjectFromWebIdentityToken']!r}"
    )
    assert assumed["Audience"] == pool_a, (
        f"Audience must be the identity pool {pool_a}, got {assumed['Audience']!r}"
    )
    assert assumed["Provider"] == COGNITO_PRINCIPAL, (
        f"Provider must name the trust policy's federated principal, got {assumed['Provider']!r}"
    )
    assert claims.get("iss") == f"https://{assumed['Provider']}", (
        f"the token issuer {claims.get('iss')!r} is not the Provider STS reports "
        f"{assumed['Provider']!r}"
    )
    assert assumed["AssumedRoleUser"]["Arn"].endswith(
        f":assumed-role/{role_a_name}/{session_name}"
    ), (
        f"AssumedRoleUser.Arn must name role/{role_a_name} and session {session_name}, got "
        f"{assumed['AssumedRoleUser']['Arn']}"
    )

    caller_arn = _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]
    assert f":assumed-role/{role_a_name}/{session_name}" in caller_arn, (
        f"the redeemed credentials must actually work and name {role_a_name}, got {caller_arn}"
    )

    # Pool B's token works against pool B's role: both roles are live and propagated, so the
    # cross denials below can only come from the aud condition.
    assumed_b = _poll_until(
        lambda: _assume(role_b_arn, token_b),
        lambda r: "Credentials" in r,
        timeout_s=180.0,
        description="sts:AssumeRoleWithWebIdentity to accept the pool B token",
    )
    assert assumed_b["Audience"] == pool_b, (
        f"pool B token Audience must be {pool_b}, got {assumed_b['Audience']!r}"
    )
    assert assumed_b["SubjectFromWebIdentityToken"] == identity_b, (
        f"pool B SubjectFromWebIdentityToken must be {identity_b}, got "
        f"{assumed_b['SubjectFromWebIdentityToken']!r}"
    )

    # Break exactly one thing: redeem each token against the other pool's role.
    for token, role_arn, token_pool, role_pool in (
        (token_a, role_b_arn, pool_a, pool_b),
        (token_b, role_a_arn, pool_b, pool_a),
    ):
        code, message = _error(lambda: _assume(role_arn, token))
        assert code == "AccessDenied", (
            f"a token for pool {token_pool} must be denied by a role scoped to pool "
            f"{role_pool}, got error code {code!r}: {message!r}"
        )
        assert message == "Not authorized to perform sts:AssumeRoleWithWebIdentity", (
            f"cross-pool denial message for a pool {token_pool} token: {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
