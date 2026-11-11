"""user-migration-trigger-creates-the-user-and-returns-tokens-on-first-sign-in."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-migration-trigger-creates-the-user-and-returns-tokens-on-first-sign-in"
GROUP = 'user-migration'
SERVICES = ['cognito-idp', 'lambda']

LEGACY_PASSWORD = "L3gacy-Directory-Passw0rd!"

_MIGRATION_CODE = """
import os

LEGACY_PASSWORD = os.environ["SIM2REAL_LEGACY_PASSWORD"]


def handler(event, context):
    # Stand-in for a legacy directory lookup: the username is unknown to Cognito, so Cognito
    # asks this trigger, and whatever it returns becomes a real persisted directory entry.
    if event["triggerSource"] == "UserMigration_Authentication":
        if event["request"]["password"] != LEGACY_PASSWORD:
            raise Exception("sim2real: no such user in the legacy directory")
        event["response"]["userAttributes"] = {
            "email": event["userName"] + "@example.com",
            "email_verified": "true",
        }
        event["response"]["finalUserStatus"] = "CONFIRMED"
        event["response"]["messageAction"] = "SUPPRESS"
    return event
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """USER_PASSWORD_AUTH for a username that does not exist invokes the UserMigration trigger,
    issues tokens, and leaves a real CONFIRMED user carrying exactly the attributes the Lambda
    returned -- who can then sign in again without the trigger.
    """
    cog = ctx.client("cognito-idp")
    trigger = _create_lambda(
        ctx, _MIGRATION_CODE, env={"SIM2REAL_LEGACY_PASSWORD": LEGACY_PASSWORD}
    )

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
    cog.update_user_pool(UserPoolId=pool_id,
                         LambdaConfig={"UserMigration": trigger["arn"]})

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    # This username is never created. It is minted here only so the migration has a subject.
    username = ctx.unique_name("sim2real-xsvc-cip-migrant-")
    migrated_email = f"{username}@example.com"

    # The precondition IS the assertion that makes this a migration and not a sign-in.
    precondition = _rejection_response(
        lambda: cog.admin_get_user(UserPoolId=pool_id, Username=username)
    )
    assert precondition["Error"]["Code"] == "UserNotFoundException", (
        f"the user already existed, so migration is not what is being graded: "
        f"{precondition['Error']['Code']!r}"
    )
    assert precondition["Error"]["Message"] == "User does not exist.", (
        f"AdminGetUser of the not-yet-migrated user answered with the wrong message: {precondition['Error']!r}"
    )

    auth = _retry_on_lambda_warmup(
        lambda: cog.initiate_auth(
            ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": LEGACY_PASSWORD},
        )
    )
    # The user now exists, so register its teardown before anything can abort.
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    assert auth.get("AuthenticationResult", {}).get("IdToken"), (
        f"the migration trigger did not yield tokens: {auth!r}"
    )

    user = cog.admin_get_user(UserPoolId=pool_id, Username=username)
    attrs = {a["Name"]: a["Value"] for a in user.get("UserAttributes", [])}
    assert attrs.get("email") == migrated_email, (
        f"the persisted user does not carry the attributes the Lambda returned: {attrs!r}"
    )
    assert user["UserStatus"] == "CONFIRMED", (
        f"finalUserStatus CONFIRMED was not honoured: {user['UserStatus']!r}"
    )

    # The migrant is a real directory entry, not a token-only side effect: it is enumerable.
    listed = []
    for page in cog.get_paginator("list_users").paginate(UserPoolId=pool_id):
        listed += [u["Username"] for u in page.get("Users", [])]
    assert username in listed, (
        f"the migrated user is not enumerable in the pool: ListUsers returned {listed!r}"
    )

    second_auth = cog.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": LEGACY_PASSWORD},
    )
    assert second_auth.get("AuthenticationResult", {}).get("AccessToken"), (
        f"the migrated user cannot sign in again, so the migration did not persist a "
        f"credential: {second_auth!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _rejection_response(fn) -> dict:
    """Return the full botocore error response of a call expected to be REJECTED.

    Raises when the call SUCCEEDS instead of returning a falsy sentinel, so an accepted invalid
    input is never reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


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
    raise AssertionError(f"the migration trigger never became invocable within "
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
    # No unconditional sleep here: IAM role trust propagation is waited out entirely by the
    # bounded "cannot be assumed" retry in _create_function_with_retry below.
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
