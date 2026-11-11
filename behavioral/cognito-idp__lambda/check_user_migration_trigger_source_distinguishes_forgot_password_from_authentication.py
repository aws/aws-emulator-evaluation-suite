"""user-migration-trigger-source-distinguishes-forgot-password-from-authentication."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-migration-trigger-source-distinguishes-forgot-password-from-authentication"
GROUP = "user-migration"
SERVICES = ["cognito-idp", "lambda"]

PASSWORD = "Sup3r-Secret-Passw0rd!"

_MIGRATION_CODE = """
import json
import os

DIRECTORY = json.loads(os.environ["SIM2REAL_LEGACY_DIRECTORY"])


def handler(event, context):
    # A stand-in legacy user store. The e-mail addresses live ONLY here, so a profile that
    # carries one proves this function ran and that Cognito honoured its response. given_name
    # is set to the triggerSource Cognito passed, which is the only way a caller can observe
    # WHICH migration event fired.
    entry = DIRECTORY.get(event["userName"])
    if entry is None:
        raise Exception("sim2real: no such user in the legacy directory")
    source = event["triggerSource"]
    if source == "UserMigration_Authentication":
        if event["request"].get("password") != entry["password"]:
            raise Exception("sim2real: legacy password does not match")
    elif source != "UserMigration_ForgotPassword":
        raise Exception("sim2real: unexpected triggerSource " + source)
    event["response"]["userAttributes"] = {
        "email": entry["email"],
        "email_verified": "true",
        "given_name": source,
    }
    event["response"]["finalUserStatus"] = "CONFIRMED"
    event["response"]["messageAction"] = "SUPPRESS"
    return event
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """One UserMigration trigger, two entry points: ForgotPassword for an unknown username migrates
    the user just as sign-in does, each profile stamped with the triggerSource Cognito sent, and a
    username the trigger refuses is rejected with UserNotFoundException and creates nothing.
    """
    cog = ctx.client("cognito-idp")
    fp_user = ctx.unique_name("sim2real-xsvc-cip-legacyfp-")
    auth_user = ctx.unique_name("sim2real-xsvc-cip-legacyauth-")
    stranger = ctx.unique_name("sim2real-xsvc-cip-stranger-")
    directory = {
        fp_user: {"email": f"{ctx.unique_name('sim2real-legacy-')}@example.com",
                  "password": PASSWORD},
        auth_user: {"email": f"{ctx.unique_name('sim2real-legacy-')}@example.com",
                    "password": PASSWORD},
    }
    trigger = _create_lambda(ctx, _MIGRATION_CODE,
                             env={"SIM2REAL_LEGACY_DIRECTORY": json.dumps(directory)})

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
    cog.update_user_pool(UserPoolId=pool_id, LambdaConfig={"UserMigration": trigger["arn"]},
                         AutoVerifiedAttributes=["email"])

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False, PreventUserExistenceErrors="LEGACY",
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    # --- baseline: none of the three usernames exists in the pool yet ---
    for name in (fp_user, auth_user, stranger):
        found = cog.list_users(UserPoolId=pool_id, Filter=f'username = "{name}"')["Users"]
        assert found == [], (
            f"{name} must not exist before migration; ListUsers returned "
            f"{[u['Username'] for u in found]}"
        )

    # --- leg 1 (first, and retried through the trigger's warm-up): the ForgotPassword path ---
    recovery = _retry_on_lambda_warmup(
        lambda: cog.forgot_password(ClientId=client_id, Username=fp_user)
    )
    delivery = recovery.get("CodeDeliveryDetails", {})
    assert delivery.get("DeliveryMedium") == "EMAIL", (
        f"the reset code for a just-migrated user must be addressed to the e-mail the trigger "
        f"supplied; CodeDeliveryDetails was {recovery.get('CodeDeliveryDetails')!r}"
    )
    assert delivery.get("AttributeName") == "email", (
        f"expected the code delivery to name the email attribute, got "
        f"{delivery.get('AttributeName')!r}"
    )
    # The trigger, not this check, created the user — but this check caused it, so it owns the
    # teardown. Registered after the pool's, so LIFO deletes the user before the pool.
    ctx.on_cleanup(
        lambda _p=pool_id, _u=fp_user: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    fp_profile = cog.admin_get_user(UserPoolId=pool_id, Username=fp_user)
    fp_attrs = {a["Name"]: a["Value"] for a in fp_profile["UserAttributes"]}
    assert fp_attrs.get("email") == directory[fp_user]["email"], (
        f"the migrated profile must carry the address that exists only inside the Lambda "
        f"({directory[fp_user]['email']}), got {fp_attrs.get('email')!r}"
    )
    assert fp_attrs.get("email_verified") == "true", (
        f"the trigger asked for email_verified=true, stored value is "
        f"{fp_attrs.get('email_verified')!r}"
    )
    assert fp_attrs.get("given_name") == "UserMigration_ForgotPassword", (
        f"the ForgotPassword entry point must invoke the trigger with triggerSource "
        f"UserMigration_ForgotPassword; the profile records "
        f"{fp_attrs.get('given_name')!r}"
    )
    # Independent read through a different operation: the migrated address is queryable.
    by_email = cog.list_users(
        UserPoolId=pool_id, Filter=f'email = "{directory[fp_user]["email"]}"'
    )["Users"]
    assert [u["Username"] for u in by_email] == [fp_user], (
        f"exactly the migrated user must be findable by the Lambda-supplied e-mail, got "
        f"{[u['Username'] for u in by_email]}"
    )

    # --- leg 2, the twin: the SAME trigger on the sign-in path, stamped differently ---
    signed_in = cog.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": auth_user, "PASSWORD": PASSWORD},
    ).get("AuthenticationResult", {})
    ctx.on_cleanup(
        lambda _p=pool_id, _u=auth_user: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    assert signed_in.get("AccessToken"), (
        f"the sign-in migration path must issue tokens, InitiateAuth returned "
        f"{sorted(signed_in)!r}"
    )
    who = cog.get_user(AccessToken=signed_in["AccessToken"])
    assert who["Username"] == auth_user, (
        f"the migrated user's token must identify {auth_user}, GetUser returned "
        f"{who.get('Username')!r}"
    )
    auth_attrs = {
        a["Name"]: a["Value"]
        for a in cog.admin_get_user(UserPoolId=pool_id, Username=auth_user)["UserAttributes"]
    }
    assert auth_attrs.get("given_name") == "UserMigration_Authentication", (
        f"the sign-in entry point must invoke the trigger with triggerSource "
        f"UserMigration_Authentication; the profile records {auth_attrs.get('given_name')!r}"
    )
    assert auth_attrs.get("given_name") != fp_attrs.get("given_name"), (
        f"the two entry points must be distinguishable by triggerSource, both profiles record "
        f"{auth_attrs.get('given_name')!r}"
    )
    assert auth_attrs.get("email") == directory[auth_user]["email"], (
        f"the sign-in-migrated profile must carry its own Lambda-supplied address "
        f"({directory[auth_user]['email']}), got {auth_attrs.get('email')!r}"
    )

    # --- the refusal: a username the source user store does not know creates nothing ---
    denial = _rejection_response(
        lambda: cog.forgot_password(ClientId=client_id, Username=stranger)
    )
    # A migration Lambda's exception on the ForgotPassword path
    # surfaces as UserNotFoundException, not UserLambdaValidationException — unlike the
    # PreAuthentication trigger's denial path. The message is the Lambda's own exception text,
    # which proves the trigger ran and refused rather than Cognito synthesising a generic
    # not-found ahead of ever invoking it.
    assert denial["Error"]["Code"] == "UserNotFoundException", (
        f"a migration trigger that throws on the ForgotPassword path must refuse the call with "
        f"UserNotFoundException, got {denial['Error']['Code']!r} (full payload "
        f"{denial!r})"
    )
    assert denial["Error"]["Message"] == (
        "UserMigration failed with error sim2real: no such user in the legacy directory."
    ), (
        f"the refusal must carry the migration Lambda's own exception text, proving the trigger "
        f"ran rather than Cognito refusing before invoking it; message was "
        f"{denial['Error']['Message']!r}"
    )
    absent = _rejection_response(
        lambda: cog.admin_get_user(UserPoolId=pool_id, Username=stranger)
    )
    assert absent["Error"]["Code"] == "UserNotFoundException", (
        f"the refused migration must have created no user; AdminGetUser answered "
        f"{absent['Error']['Code']!r} instead of UserNotFoundException"
    )
    assert absent["Error"]["Message"] == "User does not exist.", (
        f"AdminGetUser of the refused migration answered with the wrong message: {absent['Error']!r}"
    )
    listed = [
        u["Username"]
        for u in cog.list_users(UserPoolId=pool_id, Filter=f'username = "{stranger}"')["Users"]
    ]
    assert listed == [], (
        f"the refused username must not appear in ListUsers, got {listed}"
    )
    # The two users the trigger DID migrate are still there, so the refusal was specific.
    surviving = sorted(u["Username"] for u in cog.list_users(UserPoolId=pool_id)["Users"])
    assert surviving == sorted((fp_user, auth_user)), (
        f"the pool must hold exactly the two migrated users, got {surviving}"
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
    """Bounded retry over the trigger's first successful invocation. The Lambda resource policy
    Cognito needs is eventually consistent, so a first call can surface as a Lambda validation
    error before it settles -- which is exactly the code the refusal leg asserts, so the
    MIGRATING leg is retried to convergence and runs first."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("UserLambdaValidationException", "InvalidLambdaResponseException",
                            "InternalErrorException", "UserNotFoundException"):
                raise
            last = e
            time.sleep(3.0)
    raise AssertionError(
        f"the migration trigger never migrated the known legacy user within {timeout_s}s, so it "
        f"is refusing everyone rather than one username: {last!r}"
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
    """IAM roles need every attached + inline policy removed before deletion. Scoped to the one
    role this check created; failures are printed because on_cleanup swallows exceptions."""
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
    """Delete /aws/lambda/<fn_name>, waiting for the group to exist first. Never raises:
    on_cleanup swallows exceptions, so a failure here must be printed to be visible."""
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
