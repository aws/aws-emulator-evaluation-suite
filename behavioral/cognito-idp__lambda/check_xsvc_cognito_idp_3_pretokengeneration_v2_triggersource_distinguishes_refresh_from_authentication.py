"""xsvc-cognito-idp-3-pretokengeneration-v2-triggersource-distinguishes-refresh-from-authentication."""
from __future__ import annotations

import base64
import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-idp-3-pretokengeneration-v2-triggersource-distinguishes-refresh-from-authentication"
GROUP = 'custom-auth'
SERVICES = ['cognito-idp', 'lambda']

PASSWORD = "Sup3r-Secret-Passw0rd!"
CLAIM = "sim2real_trigger_source"

_V2_ECHO_TRIGGERSOURCE_CODE = """
def handler(event, context):
    # V2_0 pre-token generation: echo the EXACT triggerSource Cognito invoked us with, into the
    # ID token's own claims, so the real value can be read back from a signed, verifiable JWT
    # instead of trusted from a log line.
    event.setdefault("response", {})
    event["response"]["claimsAndScopeOverrideDetails"] = {
        "idTokenGeneration": {
            "claimsToAddOrOverride": {"sim2real_trigger_source": event.get("triggerSource", "")}
        }
    }
    return event
"""


def _decode_jwt_segment(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _id_token_claim(id_token: str, claim: str):
    return _decode_jwt_segment(id_token.split(".")[1]).get(claim)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A V2_0 PreTokenGeneration trigger sees triggerSource TokenGeneration_Authentication on a password
    sign-in and TokenGeneration_RefreshTokens on the refresh-token exchange for the same user and client,
    so the trigger runs again on refresh."""
    cog = ctx.client("cognito-idp")
    trigger = _create_lambda(ctx, _V2_ECHO_TRIGGERSOURCE_CODE)

    pool = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-trigsrc-pool-"),
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
        LambdaConfig={"PreTokenGenerationConfig": {"LambdaVersion": "V2_0",
                                                   "LambdaArn": trigger["arn"]}},
    )
    configured = cog.describe_user_pool(UserPoolId=pool_id)["UserPool"]["LambdaConfig"]
    assert configured.get("PreTokenGenerationConfig", {}).get("LambdaVersion") == "V2_0", (
        f"the pool did not retain LambdaVersion V2_0: {configured!r}"
    )

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-trigsrc-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    username = ctx.unique_name("sim2real-xsvc-cip-trigsrc-user-")
    cog.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    cog.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    # --- leg 1: a password sign-in ---
    signin = _retry_on_lambda_warmup(
        lambda: cog.initiate_auth(
            ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )
    )
    auth_result = signin.get("AuthenticationResult")
    assert auth_result, f"the password sign-in itself failed: {signin!r}"
    signin_source = _id_token_claim(auth_result["IdToken"], CLAIM)
    assert signin_source == "TokenGeneration_Authentication", (
        f"a password sign-in's PreTokenGeneration invocation did not carry the documented "
        f"triggerSource TokenGeneration_Authentication: {signin_source!r}"
    )
    refresh_token = auth_result["RefreshToken"]

    # --- leg 2: refresh, on the SAME user/client, no password involved at all ---
    refreshed = cog.initiate_auth(
        ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": refresh_token},
    )
    refreshed_result = refreshed.get("AuthenticationResult")
    assert refreshed_result, f"the refresh-token exchange failed: {refreshed!r}"
    refresh_source = _id_token_claim(refreshed_result["IdToken"], CLAIM)
    print(f"OBSERVED on real AWS: triggerSource sign-in={signin_source!r} "
          f"refresh={refresh_source!r}")
    assert refresh_source == "TokenGeneration_RefreshTokens", (
        f"a refresh-token exchange's PreTokenGeneration invocation did not carry the documented "
        f"triggerSource TokenGeneration_RefreshTokens: {refresh_source!r}"
    )
    assert refresh_source != signin_source, (
        f"the refresh leg's triggerSource equalled the sign-in leg's ({refresh_source!r}), so "
        f"the trigger either was not re-invoked on refresh or saw an identical, cached event"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _retry_on_lambda_warmup(fn, timeout_s: float = 90):
    """Bounded retry over the trigger's first successful invocation (cold start / resource-policy
    propagation). Re-raises any error that is not one of those transient codes."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("InternalErrorException", "UnexpectedLambdaException"):
                raise
            last = e
            time.sleep(3.0)
    raise AssertionError(f"the sign-in never succeeded within {timeout_s}s: {last!r}")


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
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
