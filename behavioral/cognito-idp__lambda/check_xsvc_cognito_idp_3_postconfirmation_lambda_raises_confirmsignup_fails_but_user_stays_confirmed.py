"""xsvc-cognito-idp-3-postconfirmation-lambda-raises-confirmsignup-fails-but-user-stays-confirmed."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-idp-3-postconfirmation-lambda-raises-confirmsignup-fails-but-user-stays-confirmed"
GROUP = 'triggers'
SERVICES = ['cognito-idp', 'lambda']

PASSWORD = "Sup3r-Secret-Passw0rd!"

_POSTCONFIRM_RAISES_CODE = """
def handler(event, context):
    # PostConfirmation: always raise. Cognito has already transitioned the user to CONFIRMED
    # by the time this trigger runs, and an exception here does not roll that transition back --
    # it only makes the ConfirmSignUp API CALL that triggered it fail.
    raise Exception("sim2real: PostConfirmation always raises")
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PostConfirmation Lambda that always raises makes ConfirmSignUp fail with a Lambda error,
    yet the user is left CONFIRMED: the state transition commits before the trigger runs, and
    the trigger's failure does not undo it.
    """
    cog = ctx.client("cognito-idp")
    trigger = _create_lambda(ctx, _POSTCONFIRM_RAISES_CODE)

    pool = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-postconf-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"},
        AutoVerifiedAttributes=["email"],
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda _p=pool_id: cog.delete_user_pool(UserPoolId=_p))

    ctx.client("lambda").add_permission(
        FunctionName=trigger["name"], StatementId="cognito-invoke",
        Action="lambda:InvokeFunction", Principal="cognito-idp.amazonaws.com",
        SourceArn=pool_arn,
    )
    cog.update_user_pool(UserPoolId=pool_id,
                         LambdaConfig={"PostConfirmation": trigger["arn"]})

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-postconf-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    username = ctx.unique_name("sim2real-xsvc-cip-postconf-user-")
    email = f"{username}@sim2real.example.com"
    cog.sign_up(ClientId=client_id, Username=username, Password=PASSWORD,
               UserAttributes=[{"Name": "email", "Value": email}])
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )

    before = cog.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["UserStatus"] == "UNCONFIRMED", (
        f"the just-signed-up user was not UNCONFIRMED before confirmation: "
        f"{before['UserStatus']!r}"
    )

    # There is no API that returns the SignUp confirmation code to the caller on real AWS (it
    # goes out via email/SMS, neither of which this check can receive). admin_confirm_sign_up
    # sidesteps that by confirming AS AN ADMINISTRATOR, with no code at all, which drives the
    # SAME PostConfirmation_ConfirmSignUp trigger source as the self-service confirm_sign_up call.

    # --- the one broken thing: the PostConfirmation trigger always raises ---
    error_payload = _retry_on_lambda_warmup_rejected(
        lambda: cog.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    )
    err_code = error_payload["Error"]["Code"]
    # A PostConfirmation Lambda that raises surfaces as exactly UserLambdaValidationException --
    # not the UnexpectedLambdaException a timed-out/crashed invocation produces.
    assert err_code == "UserLambdaValidationException", (
        f"a PostConfirmation Lambda raising an exception did not surface as "
        f"UserLambdaValidationException: {err_code!r} (full payload {error_payload!r})"
    )
    assert error_payload["Error"]["Message"] == "PostConfirmation failed with error sim2real: PostConfirmation always raises.", (
        f"the PostConfirmation failure did not carry the trigger's exception text: {error_payload['Error']!r}"
    )
    print(f"OBSERVED on real AWS: AdminConfirmSignUp with a raising PostConfirmation -> "
          f"Error.Code={err_code!r}")

    # (b)+(invariant): the ConfirmSignUp CALL failed, but the STATE TRANSITION it drove already
    # committed -- the user is CONFIRMED despite the API having returned an error.
    after = cog.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "CONFIRMED", (
        f"ConfirmSignUp failed via the Lambda trigger, and the user was left at "
        f"{after['UserStatus']!r} instead of CONFIRMED -- a faithful emulator must commit the "
        f"status transition BEFORE invoking PostConfirmation, exactly as real AWS does, since "
        f"the trigger's own job is to react to an already-confirmed user."
    )
    assert after["Enabled"] is True, (
        f"the user was disabled by the failed confirmation: Enabled={after['Enabled']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _retry_on_lambda_warmup_rejected(fn, timeout_s: float = 90):
    """Bounded retry over the trigger's first invocation, returning the full error response of a
    call expected to be REJECTED. Lambda cold start / resource-policy propagation can surface as
    a transient InternalErrorException before the trigger settles into its real, deterministic
    failure; only that one code is retried, and the function raises if the call unexpectedly
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
        f"ConfirmSignUp never reached its expected failure within {timeout_s}s; last={last!r}"
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
            # Registered BEFORE the function's own teardown, so LIFO runs it LAST, and it POLLS
            # for the group to exist first -- the log group is created lazily by the Lambda
            # SERVICE on first invoke, so a one-shot delete issued at function-create time races
            # it into existence and loses.
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
