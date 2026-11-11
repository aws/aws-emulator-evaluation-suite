"""xsvc-cognito-idp-3-pretokengeneration-lambda-sleeps-past-five-seconds-signin-fails."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-idp-3-pretokengeneration-lambda-sleeps-past-five-seconds-signin-fails"
GROUP = 'triggers'
SERVICES = ['cognito-idp', 'lambda']

PASSWORD = "Sup3r-Secret-Passw0rd!"

# On real AWS a PreTokenGeneration Lambda that sleeps past the
# ~5s window AWS documents for a synchronous trigger makes InitiateAuth fail with
# UnexpectedLambdaException after ~20.7-20.8s wall clock -- IDENTICAL whether the function's own
# Timeout is 20s or 60s, which is what proves the ~20s is COGNITO's own budget (apparently a
# bounded number of retries over its own short per-attempt deadline) rather than Lambda killing
# the invocation. _FUNCTION_TIMEOUT_S is set well past that observed figure so the function
# itself never kills the invocation first -- otherwise this would measure Lambda's timeout
# instead of Cognito's.
_SLEEP_S = 8
_FUNCTION_TIMEOUT_S = 60

_PRETOKEN_SLEEPS_CODE = f"""
import time

def handler(event, context):
    time.sleep({_SLEEP_S})
    event.setdefault("response", {{}})
    event["response"]["claimsOverrideDetails"] = {{
        "claimsToAddOrOverride": {{"sim2real_slow_trigger": "should-never-be-seen"}}
    }}
    return event
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A synchronous PreTokenGeneration Lambda that sleeps past the documented ~5 s trigger window
    makes the sign-in fail, although the function's own 60 s Timeout never kills it: the
    deadline is Cognito's, not the function's."""
    cog = ctx.client("cognito-idp")
    trigger = _create_lambda(ctx, _PRETOKEN_SLEEPS_CODE, timeout=_FUNCTION_TIMEOUT_S)

    pool = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-slowtrig-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"},
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda _p=pool_id: cog.delete_user_pool(UserPoolId=_p))

    ctx.client("lambda").add_permission(
        FunctionName=trigger["name"], StatementId="cognito-invoke",
        Action="lambda:InvokeFunction", Principal="cognito-idp.amazonaws.com",
        SourceArn=pool_arn,
    )
    cog.update_user_pool(UserPoolId=pool_id,
                         LambdaConfig={"PreTokenGeneration": trigger["arn"]})

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-slowtrig-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    username = ctx.unique_name("sim2real-xsvc-cip-slowtrig-user-")
    cog.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    cog.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    before = cog.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["UserStatus"] == "CONFIRMED" and before["Enabled"] is True, (
        f"the user was not usable before the sign-in attempt: {before!r}"
    )

    t0 = time.monotonic()
    error_payload = _retry_on_cold_start_rejected(
        lambda: cog.initiate_auth(
            ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )
    )
    elapsed = time.monotonic() - t0

    err_code = error_payload["Error"]["Code"]
    # On real AWS a PreTokenGeneration Lambda that never returns within Cognito's own
    # synchronous-trigger budget surfaces as exactly UnexpectedLambdaException -- not the
    # UserLambdaValidationException an explicit raise produces, so the two are asserted as two
    # different checks rather than one tuple of acceptable codes.
    assert err_code == "UnexpectedLambdaException", (
        f"a PreTokenGeneration Lambda sleeping past Cognito's own trigger deadline did not "
        f"surface as UnexpectedLambdaException: {err_code!r} "
        f"(full payload {error_payload!r}, observed after {elapsed:.1f}s)"
    )
    assert error_payload["Error"]["Message"] == (
        "PreTokenGeneration invocation failed due to error Socket timeout while invoking Lambda "
        "function."
    ), (
        f"the PreTokenGeneration timeout surfaced with the wrong message: {error_payload['Error']!r}"
    )
    print(f"OBSERVED on real AWS: InitiateAuth with a {_SLEEP_S}s-sleeping PreTokenGeneration "
          f"(function Timeout={_FUNCTION_TIMEOUT_S}s) -> Error.Code={err_code!r} after "
          f"{elapsed:.1f}s")
    assert "AuthenticationResult" not in error_payload, (
        f"tokens accompanied the failure: {sorted(error_payload)!r}"
    )
    # The failure must come from COGNITO'S OWN deadline, not from the FUNCTION's Timeout killing
    # the invocation -- that would be a different (and far less interesting) failure mode, and
    # would mean this check is not exercising what it claims to.
    assert elapsed < _FUNCTION_TIMEOUT_S, (
        f"the sign-in failure took {elapsed:.1f}s, at or past the function's own "
        f"{_FUNCTION_TIMEOUT_S}s Timeout -- this measured Lambda killing the invocation, not "
        f"Cognito's independent synchronous-trigger deadline"
    )

    # (b): the effect is absent -- no overridden claim was ever observed, since the trigger that
    # would have added it never got to finish within Cognito's deadline.
    after = cog.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "CONFIRMED" and after["Enabled"] is True, (
        f"the timed-out trigger mutated the user: {after!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _retry_on_cold_start_rejected(fn, timeout_s: float = 90):
    """Bounded retry over Lambda cold start / resource-policy propagation only, returning the
    full error response of a call expected to be REJECTED. Raises if the call unexpectedly
    SUCCEEDS rather than returning a falsy sentinel."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InternalErrorException":
                last = e.response
                time.sleep(3.0)
                continue
            return e.response
        last = result
        time.sleep(3.0)
    if isinstance(last, dict) and "Error" in last:
        return last
    raise AssertionError(
        f"InitiateAuth never reached its expected failure within {timeout_s}s; last={last!r}"
    )


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
