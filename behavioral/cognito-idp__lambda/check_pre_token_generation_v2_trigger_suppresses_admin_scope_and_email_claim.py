"""pre-token-generation-v2-trigger-suppresses-admin-scope-and-email-claim."""
from __future__ import annotations

import base64
import json
import textwrap
import time
import urllib.request
import zipfile
from hashlib import sha256
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pre-token-generation-v2-trigger-suppresses-admin-scope-and-email-claim"
GROUP = "token-customization"
SERVICES = ["cognito-idp", "iam", "lambda", "logs"]

_PREFIX = "sim2real-cip-suppress-"
_PASSWORD = "Qx7!Trombone-Lamp9"
_RESERVED_SCOPE = "aws.cognito.signin.user.admin"
_EMAIL_CLAIM = "email"
_POOL_DELETE_THROTTLE = ("TooManyRequestsException", "Rate exceeded")

_TRIGGER_CODE = """
import os

SCOPE = os.environ["SIM2REAL_SCOPE_TO_SUPPRESS"]
CLAIM = os.environ["SIM2REAL_CLAIM_TO_SUPPRESS"]


def handler(event, context):
    event.setdefault("response", {})
    event["response"]["claimsAndScopeOverrideDetails"] = {
        "accessTokenGeneration": {"scopesToSuppress": [SCOPE]},
        "idTokenGeneration": {"claimsToSuppress": [CLAIM]},
    }
    return event
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A V2_0 PreTokenGeneration trigger suppressing accessTokenGeneration.scopesToSuppress and
    idTokenGeneration.claimsToSuppress removes the named scope and claim from the signed tokens
    AdminInitiateAuth issues, while a baseline sign-in with no trigger attached carries both.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
    """
    cog = ctx.client("cognito-idp")
    lam = ctx.client("lambda")

    trigger = _create_trigger_function(ctx, env={
        "SIM2REAL_SCOPE_TO_SUPPRESS": _RESERVED_SCOPE,
        "SIM2REAL_CLAIM_TO_SUPPRESS": _EMAIL_CLAIM,
    })

    pool = cog.create_user_pool(
        PoolName=ctx.unique_name(f"{_PREFIX}pool-"),
        UserPoolTier="ESSENTIALS",
        UserPoolTags={"sim2real": "pre-token-generation-v2-trigger-suppresses"},
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda _p=pool_id: _detach_trigger_and_delete_pool(cog, _p))

    lam.add_permission(
        FunctionName=trigger["name"], StatementId="cognito-invoke",
        Action="lambda:InvokeFunction", Principal="cognito-idp.amazonaws.com",
        SourceArn=pool_arn,
    )

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name(f"{_PREFIX}client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: _ignore_not_found(
            lambda: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
        )
    )

    username = ctx.unique_name(f"{_PREFIX}user-")
    email = f"{username}@example.com"
    cog.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": email},
                        {"Name": "email_verified", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: _ignore_not_found(
            lambda: cog.admin_delete_user(UserPoolId=_p, Username=_u)
        )
    )
    cog.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True
    )

    # Positive control: before any trigger is attached, the reserved API scope and the verified
    # email claim are both present, so their later absence can only come from the trigger.
    baseline = cog.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )["AuthenticationResult"]
    baseline_access = _verified_claims(cog, pool_id, baseline["AccessToken"])
    baseline_id = _verified_claims(cog, pool_id, baseline["IdToken"])
    assert _RESERVED_SCOPE in (baseline_access.get("scope") or "").split(), (
        f"the baseline access token (no trigger attached) does not carry the reserved scope "
        f"{_RESERVED_SCOPE!r}, so its later absence would prove nothing: "
        f"{baseline_access.get('scope')!r}"
    )
    assert baseline_id.get(_EMAIL_CLAIM) == email, (
        f"the baseline ID token (no trigger attached) does not carry the verified "
        f"{_EMAIL_CLAIM!r} claim, so its later absence would prove nothing: "
        f"{sorted(baseline_id)!r}"
    )

    cog.update_user_pool(
        UserPoolId=pool_id,
        LambdaConfig={"PreTokenGenerationConfig": {"LambdaVersion": "V2_0",
                                                   "LambdaArn": trigger["arn"]}},
    )
    configured = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]["LambdaConfig"]
    assert configured["PreTokenGenerationConfig"]["LambdaVersion"] == "V2_0", (
        f"the pool did not retain LambdaVersion V2_0 after attaching the trigger: {configured!r}"
    )

    shaped = _retry_while_trigger_warms_up(lambda: cog.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    ))["AuthenticationResult"]
    shaped_access = _verified_claims(cog, pool_id, shaped["AccessToken"])
    shaped_id = _verified_claims(cog, pool_id, shaped["IdToken"])

    assert _RESERVED_SCOPE not in (shaped_access.get("scope") or "").split(), (
        f"the trigger suppressed {_RESERVED_SCOPE!r}, but it is still in the access token scope: "
        f"{shaped_access.get('scope')!r}"
    )
    assert _EMAIL_CLAIM not in shaped_id, (
        f"the trigger suppressed {_EMAIL_CLAIM!r}, but it is still in the ID token: "
        f"{sorted(shaped_id)!r}"
    )


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last seen {last!r}")


def _decode_jwt_segment(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _segment_to_int(segment: str) -> int:
    padding = "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(segment + padding), "big")


def _rsa_pkcs1v15_sha256_verifies(message: bytes, signature: bytes, modulus_b64: str,
                                  exponent_b64: str) -> bool:
    """RSASSA-PKCS1-v1_5 (RS256) signature check, built from the raw modulus/exponent only."""
    modulus = _segment_to_int(modulus_b64)
    exponent = _segment_to_int(exponent_b64)
    byte_len = (modulus.bit_length() + 7) // 8
    recovered = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(
        byte_len, "big"
    )
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + sha256(message).digest()
    padding_len = byte_len - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info
    return recovered == expected


def _verified_claims(cog, pool_id: str, token: str) -> dict:
    """Fetch the pool's JWKS, verify the token's RS256 signature, and return its claims."""
    header_b64, payload_b64, signature_b64 = token.split(".")
    key_id = _decode_jwt_segment(header_b64).get("kid")
    jwks_url = f"{cog.meta.endpoint_url.rstrip('/')}/{pool_id}/.well-known/jwks.json"
    with urllib.request.urlopen(jwks_url, timeout=30) as resp:  # noqa: S310 - fixed https scheme
        jwks = json.loads(resp.read().decode())
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == key_id), None)
    assert key is not None, f"signing key {key_id!r} is absent from the pool JWKS {jwks!r}"
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
    assert _rsa_pkcs1v15_sha256_verifies(signing_input, signature, key["n"], key["e"]), (
        f"the shaped token does not verify against the pool's own published JWKS key {key_id!r}"
    )
    return _decode_jwt_segment(payload_b64)


def _retry_while_trigger_warms_up(fn, timeout_s: float = 90.0):
    """The trigger's Lambda invoke permission is eventually consistent, so the first sign-in
    after attaching it can surface a validation error before the grant has propagated."""
    deadline = time.monotonic() + timeout_s
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("UserLambdaValidationException", "InvalidLambdaResponseException"):
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"the trigger never became invocable within {timeout_s}s: {last!r}")


def _detach_trigger_and_delete_pool(cog, pool_id: str) -> None:
    """Clear LambdaConfig (so the pool never again invokes the about-to-be-deleted function),
    then delete the pool, retried only on Cognito's own throttling pair."""
    try:
        cog.update_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    attempts = 0
    while True:
        try:
            cog.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            attempts += 1
            if (err["Code"], err["Message"]) != _POOL_DELETE_THROTTLE or attempts >= 10:
                if err["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(2.0 * attempts)


def _make_execution_role(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"{_PREFIX}role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    created = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="logs",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                          "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                     "logs:PutLogEvents"],
                          "Resource": "arn:aws:logs:*:*:*"}],
        }),
    )
    return {"name": role_name, "arn": created["Role"]["Arn"]}


def _delete_role(iam, role_name: str) -> None:
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_trigger_function(ctx, env: dict[str, str]) -> dict[str, str]:
    """Create the Lambda the pool will invoke, retrying through IAM role propagation, then
    wait for it to become Active. Its teardown is registered first, so LIFO runs it last --
    after the pool that references it is already gone."""
    role = _make_execution_role(ctx)
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"{_PREFIX}fn-")
    code = textwrap.dedent(_TRIGGER_CODE)
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    kwargs: dict[str, Any] = {
        "FunctionName": name, "Runtime": "python3.12", "Role": role["arn"],
        "Handler": "lambda_function.handler", "Code": {"ZipFile": buf.getvalue()},
        "Timeout": 15, "MemorySize": 128, "Environment": {"Variables": env},
        "Tags": {"sim2real": "pre-token-generation-v2-trigger-suppresses"},
    }
    deadline = time.monotonic() + 60.0
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            created = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            _poll_until(lambda: lam.get_function_configuration(FunctionName=name),
                       lambda r: r.get("State") == "Active", timeout_s=90.0, interval_s=2.0,
                       description=f"Lambda {name} Active")
            return {"name": name, "arn": created["FunctionArn"]}
        except ClientError as exc:
            if "cannot be assumed" in str(exc) or exc.response["Error"]["Code"] == (
                "InvalidParameterValueException"
            ):
                last_err = exc
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"could not create trigger function {name}: {last_err!r}")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete the function's log group until it stays absent for several consecutive reads --
    a buffered invocation can flush and recreate it right after the function is deleted."""
    deadline = time.monotonic() + budget_s
    consecutive_absent = 0
    while consecutive_absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            consecutive_absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            consecutive_absent += 1
        if consecutive_absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still reappearing after {budget_s}s of deletes"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
