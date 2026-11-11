"""custom-auth-challenge-triad-issues-tokens-only-after-the-secret-answer."""
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

CHECK = "custom-auth-challenge-triad-issues-tokens-only-after-the-secret-answer"
GROUP = 'custom-auth'
SERVICES = ['cognito-idp', 'lambda']

QUESTION = "what-does-sim2real-grade"
ANSWER = "the-data-plane"

_TRIAD_CODE = """
import os

QUESTION = os.environ["SIM2REAL_QUESTION"]
ANSWER = os.environ["SIM2REAL_ANSWER"]


def handler(event, context):
    # One function implements all three CUSTOM_AUTH triggers, switching on triggerSource.
    src = event["triggerSource"]
    resp = event.setdefault("response", {})
    if src.startswith("DefineAuthChallenge"):
        session = event["request"].get("session") or []
        if not session:
            resp["challengeName"] = "CUSTOM_CHALLENGE"
            resp["issueTokens"] = False
            resp["failAuthentication"] = False
        elif session[-1].get("challengeResult"):
            resp["issueTokens"] = True
            resp["failAuthentication"] = False
        else:
            resp["issueTokens"] = False
            resp["failAuthentication"] = True
    elif src.startswith("CreateAuthChallenge"):
        resp["publicChallengeParameters"] = {"question": QUESTION}
        resp["privateChallengeParameters"] = {"answer": ANSWER}
        resp["challengeMetadata"] = "SIM2REAL_QA"
    elif src.startswith("VerifyAuthChallengeResponse"):
        expected = event["request"]["privateChallengeParameters"]["answer"]
        resp["answerCorrect"] = event["request"]["challengeAnswer"] == expected
    return event
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CUSTOM_AUTH flow driven by real Define/Create/VerifyAuthChallenge Lambdas returns the
    challenge parameters the Create trigger published and issues a full token set only after
    the answer the Verify trigger accepts.
    """
    cog = ctx.client("cognito-idp")
    trigger = _create_lambda(
        ctx, _TRIAD_CODE, env={"SIM2REAL_QUESTION": QUESTION, "SIM2REAL_ANSWER": ANSWER}
    )

    # The pool is created bare so the Lambda resource policy can name its ARN before the
    # triggers are attached -- Cognito validates the policy at the moment LambdaConfig is set.
    pool = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"},
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda _p=pool_id: cog.delete_user_pool(UserPoolId=_p))

    ctx.client("lambda").add_permission(
        FunctionName=trigger["name"], StatementId="cognito-invoke",
        Action="lambda:InvokeFunction", Principal="cognito-idp.amazonaws.com",
        SourceArn=pool_arn,
    )
    cog.update_user_pool(
        UserPoolId=pool_id,
        LambdaConfig={
            "DefineAuthChallenge": trigger["arn"],
            "CreateAuthChallenge": trigger["arn"],
            "VerifyAuthChallengeResponse": trigger["arn"],
        },
    )

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-client-"),
        ExplicitAuthFlows=["ALLOW_CUSTOM_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    username = ctx.unique_name("sim2real-xsvc-cip-user-")
    cog.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    cog.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password="Sup3r-Secret-Passw0rd!", Permanent=True
    )

    init = _retry_on_lambda_warmup(
        lambda: cog.initiate_auth(
            ClientId=client_id, AuthFlow="CUSTOM_AUTH",
            AuthParameters={"USERNAME": username},
        )
    )
    assert init["ChallengeName"] == "CUSTOM_CHALLENGE", (
        f"the Define trigger did not drive a custom challenge: {init!r}"
    )
    assert init["ChallengeParameters"].get("question") == QUESTION, (
        f"the Create trigger's public parameters did not reach the client: "
        f"{init['ChallengeParameters']!r}"
    )
    assert "AuthenticationResult" not in init, (
        f"tokens were issued before the challenge was answered: {sorted(init)!r}"
    )

    resp = cog.respond_to_auth_challenge(
        ClientId=client_id, ChallengeName="CUSTOM_CHALLENGE", Session=init["Session"],
        ChallengeResponses={"USERNAME": username, "ANSWER": ANSWER},
    )
    assert set(resp.get("AuthenticationResult", {})) >= {"IdToken", "AccessToken", "RefreshToken"}, (
        f"the answered challenge did not yield a full token set: "
        f"{sorted(resp.get('AuthenticationResult', {}))!r}"
    )

    claims = _verify_jwt_against_jwks(cog, pool_id, resp["AuthenticationResult"]["IdToken"])
    assert claims["cognito:username"] == username, (
        f"the id token names the wrong user: {claims!r}"
    )
    assert claims["token_use"] == "id", (
        f"the wrong token was inspected: {claims['token_use']!r}"
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
        f"the minted token does not verify against the pool JWKS key {kid!r}"
    )
    return _decode_jwt_segment(payload_b64)


def _retry_on_lambda_warmup(fn, timeout_s: float = 90):
    """Bounded retry over the trigger's first invocation. The Lambda resource policy Cognito
    needs is eventually consistent, so the FIRST auth can surface as
    UserLambdaValidationException/InvalidLambdaResponseException before it settles; every later
    call in the check runs against a warm, authorised trigger."""
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
    raise AssertionError(f"the custom-auth trigger never became invocable within "
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
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


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
