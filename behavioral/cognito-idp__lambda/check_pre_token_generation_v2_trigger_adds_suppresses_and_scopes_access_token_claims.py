"""pre-token-generation-v2-trigger-adds-suppresses-and-scopes-access-token-claims."""
from __future__ import annotations

import base64
import hashlib
import json
import textwrap
import time
import urllib.request
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pre-token-generation-v2-trigger-adds-suppresses-and-scopes-access-token-claims"
GROUP = 'custom-auth'
SERVICES = ['cognito-idp', 'lambda']

PASSWORD = "Sup3r-Secret-Passw0rd!"
ADDED_CLAIM = "custom_tier"
ADDED_VALUE = "gold"
ADDED_SCOPE = "sim2real/read"
SUPPRESSED_CLAIM = "cognito:groups"

_V2_CODE = """
import os

ADDED_CLAIM = os.environ["SIM2REAL_ADDED_CLAIM"]
ADDED_VALUE = os.environ["SIM2REAL_ADDED_VALUE"]
ADDED_SCOPE = os.environ["SIM2REAL_ADDED_SCOPE"]
SUPPRESSED_CLAIM = os.environ["SIM2REAL_SUPPRESSED_CLAIM"]


def handler(event, context):
    # V2_0 pre-token generation shapes the ACCESS token, which V1_0 cannot touch at all.
    event["response"]["claimsAndScopeOverrideDetails"] = {
        "accessTokenGeneration": {
            "claimsToAddOrOverride": {ADDED_CLAIM: ADDED_VALUE},
            "claimsToSuppress": [SUPPRESSED_CLAIM],
            "scopesToAdd": [ADDED_SCOPE],
        }
    }
    return event
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A V2_0 PreTokenGeneration trigger that adds a claim, suppresses another and adds a scope
    yields a JWKS-verified ACCESS token with the added claim and scope and without the suppressed
    one -- which the user genuinely has, because they are in a group.
    """
    cog = ctx.client("cognito-idp")
    trigger = _create_lambda(ctx, _V2_CODE, env={
        "SIM2REAL_ADDED_CLAIM": ADDED_CLAIM, "SIM2REAL_ADDED_VALUE": ADDED_VALUE,
        "SIM2REAL_ADDED_SCOPE": ADDED_SCOPE, "SIM2REAL_SUPPRESSED_CLAIM": SUPPRESSED_CLAIM,
    })

    pool = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"},
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda _p=pool_id: _delete_pool_with_retry(cog, _p))

    ctx.client("lambda").add_permission(
        FunctionName=trigger["name"], StatementId="cognito-invoke",
        Action="lambda:InvokeFunction", Principal="cognito-idp.amazonaws.com",
        SourceArn=pool_arn,
    )

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    group_name = ctx.unique_name("sim2real-xsvc-cip-group-")
    cog.create_group(UserPoolId=pool_id, GroupName=group_name)
    ctx.on_cleanup(
        lambda _p=pool_id, _g=group_name: cog.delete_group(UserPoolId=_p, GroupName=_g)
    )

    username = ctx.unique_name("sim2real-xsvc-cip-user-")
    cog.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    cog.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )
    cog.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_name)
    # The group membership must be real, or "cognito:groups is absent" is vacuous.
    memberships = []
    for page in cog.get_paginator("admin_list_groups_for_user").paginate(
            UserPoolId=pool_id, Username=username):
        memberships += [g["GroupName"] for g in page.get("Groups", [])]
    assert group_name in memberships, (
        f"the user is not in the group, so a suppressed {SUPPRESSED_CLAIM!r} claim would be "
        f"vacuous: {memberships!r}"
    )

    # Positive control: before any trigger is attached, this group member's access token already
    # carries cognito:groups, so the later absence can only come from the trigger's suppression.
    baseline_auth = cog.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )
    baseline_claims = _verify_jwt_against_jwks(
        cog, pool_id, baseline_auth["AuthenticationResult"]["AccessToken"]
    )
    assert group_name in (baseline_claims.get(SUPPRESSED_CLAIM) or []), (
        f"the baseline access token (no trigger attached yet) does not carry "
        f"{SUPPRESSED_CLAIM!r} for a group member, so its later absence would prove nothing: "
        f"{sorted(baseline_claims)!r}"
    )

    cog.update_user_pool(
        UserPoolId=pool_id,
        LambdaConfig={"PreTokenGenerationConfig": {"LambdaVersion": "V2_0",
                                                   "LambdaArn": trigger["arn"]}},
    )
    # Read the config back: a service that silently downgraded V2_0 to V1_0 would make every
    # access-token assertion below fail for the wrong reason.
    configured = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]["LambdaConfig"]
    assert configured["PreTokenGenerationConfig"]["LambdaVersion"] == "V2_0", (
        f"the pool did not retain LambdaVersion V2_0: {configured!r}"
    )

    auth = _retry_on_lambda_warmup(
        lambda: cog.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]
    claims = _verify_jwt_against_jwks(cog, pool_id, access_token)

    assert claims["token_use"] == "access", (
        f"the wrong token was inspected: {claims['token_use']!r}"
    )
    assert claims.get(ADDED_CLAIM) == ADDED_VALUE, (
        f"the trigger's added claim did not reach the access token: {sorted(claims)!r}"
    )
    assert SUPPRESSED_CLAIM not in claims, (
        f"the suppressed claim is still present even though the trigger removed it: "
        f"{sorted(claims)!r}"
    )
    assert ADDED_SCOPE in (claims.get("scope") or "").split(), (
        f"the added scope is missing from the access token: {claims.get('scope')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _decode_jwt_segment(segment: str) -> dict:
    """base64url-decode a JWT header/payload segment into a dict (no signature verify)."""
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _b64url_to_int(segment: str) -> int:
    padding = "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(segment + padding), "big")


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    """Verify an RS256 (RSASSA-PKCS1-v1_5, SHA-256) JWT signature against a JWK public key --
    pure Python, no external crypto dependency."""
    n = _b64url_to_int(jwk["n"])
    e = _b64url_to_int(jwk["e"])
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")  # SHA-256 DigestInfo DER
    ps_len = k - len(prefix) - len(digest) - 3
    return em == b"\x00\x01" + b"\xff" * ps_len + b"\x00" + prefix + digest


def _verify_jwt_against_jwks(client, pool_id: str, token: str) -> dict:
    """Fetch the pool's published JWKS, verify token's RS256 signature, return its claims."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    kid = _decode_jwt_segment(header_b64).get("kid")
    url = f"{client.meta.endpoint_url.rstrip('/')}/{pool_id}/.well-known/jwks.json"
    with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 - fixed scheme from the client
        jwks = json.loads(r.read().decode())
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    assert jwk is not None, f"kid {kid!r} is absent from the pool JWKS {jwks!r}"
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    assert _verify_rs256(signing_input, signature, jwk) is True, (
        f"the shaped access token does not verify against the pool JWKS key {kid!r}"
    )
    return _decode_jwt_segment(payload_b64)


def _retry_on_lambda_warmup(fn, timeout_s: float = 90):
    """Bounded retry over the trigger's first invocation. The Lambda resource policy Cognito
    needs is eventually consistent, so the FIRST auth can surface as a Lambda validation error
    before it settles; every later call in this check runs against a warm, authorised trigger."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("UserLambdaValidationException", "InvalidLambdaResponseException",
                            "InternalErrorException"):
                raise
            last = e
            time.sleep(3.0)
    raise AssertionError(f"the pre-token-generation trigger never became invocable within "
                         f"{timeout_s}s: {last!r}")


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service},
                            "Action": "sts:AssumeRole"}]}
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                           Path="/sim2real/", Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                            PolicyDocument=json.dumps(inline_policy))
    # IAM role trust propagation is eventually consistent; no fixed sleep can bound it, so the
    # wait lives entirely in _create_function_with_retry's bounded "cannot be assumed" retry.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_pool_with_retry(cog, pool_id: str, timeout_s: float = 45.0) -> None:
    """Delete the user pool, retrying through the window where Cognito still treats it as
    concurrently modified right after the LambdaConfig update and the auths this check just ran.
    A one-shot delete loses that race often enough to leak the pool; never raises, since
    on_cleanup swallows exceptions anyway."""
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cog.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            last = e
            time.sleep(3.0)
    raise RuntimeError(
        f"user pool {pool_id} could not be deleted within {timeout_s}s: {last!r}"
    )


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function_with_retry(ctx, handler_code, role_arn, env, timeout=30,
                                memory=128, runtime="python3.12") -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait Active."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name, "Runtime": runtime, "Role": role_arn,
        "Handler": "lambda_function.lambda_handler", "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout, "MemorySize": memory,
        "Tags": {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")},
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            # Registered BEFORE the function's own teardown, so LIFO runs it LAST, and it POLLS:
            # Lambda creates /aws/lambda/<name> lazily after the invocation returns, so a one-shot
            # delete races it and the group materialises seconds later.
            ctx.on_cleanup(lambda: _delete_log_group_when_it_appears(ctx, name))
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            _poll_until(lambda: lam.get_function_configuration(FunctionName=name),
                        lambda r: r.get("State") == "Active", timeout_s=90, interval_s=2.0,
                        description=f"Lambda {name} active")
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _delete_log_group_when_it_appears(ctx, fn_name: str, timeout_s: float = 45.0) -> None:
    """Delete /aws/lambda/<fn_name>, waiting for the group to exist first.

    The group is created by the Lambda SERVICE, asynchronously, so a delete issued the instant a
    check ends races it and loses. Polling the delete itself -- rather than sleeping -- makes the
    teardown converge on the observable condition. Never raises: on_cleanup swallows exceptions,
    so a failure here must be printed to be visible at all."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise RuntimeError(
                    f"/aws/lambda/{fn_name} could not be deleted: {e!r}"
                ) from e
            time.sleep(2.0)
    raise RuntimeError(
        f"/aws/lambda/{fn_name} never appeared within {timeout_s}s and was not deleted"
    )


def _create_lambda(ctx, handler_code, env=None, timeout=30, memory=128,
                   runtime="python3.12") -> dict[str, str]:
    """Create a Lambda with a logs-only execution role. Role + function each register their
    own teardown (function torn down first, LIFO)."""
    role = _create_role(ctx, "lambda.amazonaws.com", inline_policy={
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                  "logs:PutLogEvents"],
                       "Resource": "arn:aws:logs:*:*:*"}]})
    return _create_function_with_retry(ctx, handler_code, role["arn"], env or {}, timeout,
                                       memory, runtime)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
