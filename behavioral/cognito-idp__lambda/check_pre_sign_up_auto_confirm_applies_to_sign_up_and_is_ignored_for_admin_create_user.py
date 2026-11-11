"""pre-sign-up-auto-confirm-applies-to-sign-up-and-is-ignored-for-admin-create-user."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pre-sign-up-auto-confirm-applies-to-sign-up-and-is-ignored-for-admin-create-user"
GROUP = "triggers"
SERVICES = ["cognito-idp", "lambda"]

PASSWORD = "Sup3r-Secret-Passw0rd!"

_PRESIGNUP_CODE = """
import os

DENIED_MARKER = os.environ["SIM2REAL_DENIED_MARKER"]


def handler(event, context):
    # PreSignUp: refuse exactly one username, and ask for auto-confirmation plus
    # auto-verification for every other one. Cognito HONOURS these response fields on the
    # SignUp path and IGNORES them on the AdminCreateUser path, which is the asymmetry under
    # test -- the Lambda itself cannot tell the difference and does not try to.
    if DENIED_MARKER in event["userName"]:
        raise Exception("sim2real: PreSignUp refuses this username")
    event["response"]["autoConfirmUser"] = True
    if "email" in event["request"]["userAttributes"]:
        event["response"]["autoVerifyEmail"] = True
    return event
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PreSignUp autoConfirmUser/autoVerifyEmail response confirms a SignUp user but is ignored
    by AdminCreateUser (FORCE_CHANGE_PASSWORD); a throw on AdminCreateUser proves it still runs.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-sign-up.html
    """
    cog = ctx.client("cognito-idp")
    denied_marker = "denyme"
    trigger = _create_lambda(ctx, _PRESIGNUP_CODE,
                             env={"SIM2REAL_DENIED_MARKER": denied_marker})

    pool = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-pool-"),
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"},
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda _p=pool_id: cog.delete_user_pool(UserPoolId=_p))

    ctx.client("lambda").add_permission(
        FunctionName=trigger["name"], StatementId="cognito-invoke",
        Action="lambda:InvokeFunction", Principal="cognito-idp.amazonaws.com",
        SourceArn=pool_arn,
    )
    # UpdateUserPool resets omitted fields to their defaults, so AutoVerifiedAttributes is
    # re-sent rather than assumed to survive attaching the trigger.
    cog.update_user_pool(UserPoolId=pool_id, LambdaConfig={"PreSignUp": trigger["arn"]},
                         AutoVerifiedAttributes=["email"])

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    # --- leg 1 (the positive control, deliberately first): the SignUp path honours the trigger.
    # An un-propagated Lambda resource policy also surfaces as UserLambdaValidationException, so
    # the refusal leg below would pass for the wrong reason if the trigger were not first proved
    # invocable.
    signed_up_name = ctx.unique_name("sim2real-xsvc-cip-selfsignup-")
    signed_up_email = f"{signed_up_name}@example.com"
    signed_up = _retry_on_lambda_warmup(
        lambda: cog.sign_up(
            ClientId=client_id, Username=signed_up_name, Password=PASSWORD,
            UserAttributes=[{"Name": "email", "Value": signed_up_email}],
        )
    )
    ctx.on_cleanup(
        lambda _p=pool_id, _u=signed_up_name: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    assert signed_up.get("UserConfirmed") is True, (
        f"autoConfirmUser=true must make SignUp report UserConfirmed=true, got "
        f"{signed_up.get('UserConfirmed')!r}"
    )
    self_signup = cog.admin_get_user(UserPoolId=pool_id, Username=signed_up_name)
    assert self_signup["UserStatus"] == "CONFIRMED", (
        f"the self-signed-up user must be CONFIRMED without any ConfirmSignUp call, "
        f"AdminGetUser reports {self_signup['UserStatus']!r}"
    )
    self_attrs = {a["Name"]: a["Value"] for a in self_signup["UserAttributes"]}
    assert self_attrs.get("email_verified") == "true", (
        f"autoVerifyEmail=true must store email_verified='true', got "
        f"{self_attrs.get('email_verified')!r} (attributes {sorted(self_attrs)})"
    )
    # The consequence, read at the consumer of the confirmation: the user can sign in.
    tokens = cog.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": signed_up_name, "PASSWORD": PASSWORD},
    ).get("AuthenticationResult", {})
    assert tokens.get("AccessToken"), (
        f"an auto-confirmed user must be able to sign in immediately, InitiateAuth returned "
        f"{sorted(tokens)!r}"
    )
    who = cog.get_user(AccessToken=tokens["AccessToken"])
    assert who["Username"] == signed_up_name, (
        f"the auto-confirmed user's token must identify {signed_up_name}, GetUser returned "
        f"{who.get('Username')!r}"
    )

    # --- leg 2: the AdminCreateUser path ignores the SAME trigger response ---
    invited_name = ctx.unique_name("sim2real-xsvc-cip-invited-")
    invited_email = f"{invited_name}@example.com"
    # A known TemporaryPassword is required so the InitiateAuth probe below can authenticate
    # with it: AdminCreateUser generates a random one when omitted, which MessageAction=SUPPRESS
    # never delivers, leaving no password this check could ever present.
    cog.admin_create_user(
        UserPoolId=pool_id, Username=invited_name, MessageAction="SUPPRESS",
        TemporaryPassword=PASSWORD,
        UserAttributes=[{"Name": "email", "Value": invited_email}],
    )
    ctx.on_cleanup(
        lambda _p=pool_id, _u=invited_name: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    invited = cog.admin_get_user(UserPoolId=pool_id, Username=invited_name)
    assert invited["UserStatus"] == "FORCE_CHANGE_PASSWORD", (
        f"AdminCreateUser must IGNORE the trigger's autoConfirmUser and leave the user at "
        f"FORCE_CHANGE_PASSWORD, AdminGetUser reports {invited['UserStatus']!r} — the same "
        f"trigger response left the self-signed-up user CONFIRMED, which is the asymmetry"
    )
    invited_attrs = {a["Name"]: a["Value"] for a in invited["UserAttributes"]}
    assert invited_attrs.get("email_verified") != "true", (
        f"AdminCreateUser must IGNORE the trigger's autoVerifyEmail, but email_verified is "
        f"{invited_attrs.get('email_verified')!r}"
    )
    invited_auth = cog.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": invited_name, "PASSWORD": PASSWORD},
    )
    assert invited_auth.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", (
        f"the invited user must be challenged for a new password rather than signed in, got "
        f"ChallengeName={invited_auth.get('ChallengeName')!r}"
    )
    assert "AuthenticationResult" not in invited_auth, (
        f"tokens were issued to a user AdminCreateUser should have left unconfirmed: "
        f"{sorted(invited_auth)!r}"
    )

    # --- leg 3: the trigger DOES run on the AdminCreateUser path, proved by making it throw ---
    denied_name = ctx.unique_name(f"sim2real-xsvc-cip-{denied_marker}-")
    denial = _rejection_response(
        lambda: cog.admin_create_user(
            UserPoolId=pool_id, Username=denied_name, MessageAction="SUPPRESS",
            UserAttributes=[{"Name": "email", "Value": f"{denied_name}@example.com"}],
        )
    )
    assert denial["Error"]["Code"] == "UserLambdaValidationException", (
        f"a PreSignUp throw on the AdminCreateUser path must surface as "
        f"UserLambdaValidationException, got {denial['Error']['Code']!r} (full payload {denial!r})"
    )
    assert denial["Error"]["Message"] == "PreSignUp failed with error sim2real: PreSignUp refuses this username.", (
        f"the PreSignUp denial did not carry the trigger's exception text: {denial['Error']!r}"
    )
    absent = _rejection_response(
        lambda: cog.admin_get_user(UserPoolId=pool_id, Username=denied_name)
    )
    assert absent["Error"]["Code"] == "UserNotFoundException", (
        f"the refused sign-up must have created no user; AdminGetUser answered "
        f"{absent['Error']['Code']!r} instead of UserNotFoundException"
    )
    assert absent["Error"]["Message"] == "User does not exist.", (
        f"AdminGetUser of the refused user answered with the wrong message: {absent['Error']!r}"
    )
    listed = [
        u["Username"]
        for u in cog.list_users(UserPoolId=pool_id, Filter=f'username = "{denied_name}"')["Users"]
    ]
    assert listed == [], (
        f"the refused username must not appear in ListUsers, got {listed}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _rejection_response(fn) -> dict:
    """Return the error response of a call expected to be rejected; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


def _retry_on_lambda_warmup(fn, timeout_s: float = 90):
    """Retry until the trigger first succeeds: the Lambda resource policy Cognito needs is
    eventually consistent, so early calls can fail with a Lambda validation error."""
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
    raise AssertionError(
        f"the trigger never let a sign-up through within {timeout_s}s, so it is refusing "
        f"everyone rather than one username: {last!r}"
    )


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result. Raises on
    timeout — never returns the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
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
    """Delete a role after removing its attached and inline policies."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        teardown_code = e.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(f"role {role_name} could not be deleted: {e!r}") from e


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
            # Lambda creates /aws/lambda/<name> lazily, after the first invocation returns, so a
            # one-shot delete loses the race and strands the log group.
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
    """Delete /aws/lambda/<fn_name>, waiting for the group to exist first."""
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
    """Create a Lambda with a logs-only execution role. Role + function each register their own
    teardown (function torn down first, LIFO)."""
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
