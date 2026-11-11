"""custom-auth-wrong-answer-rejected-and-no-token-is-issued."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-auth-wrong-answer-rejected-and-no-token-is-issued"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp', 'lambda']

QUESTION = "what-does-sim2real-grade"
ANSWER = "the-data-plane"
WRONG_ANSWER = "the-control-plane"
PASSWORD = "Sup3r-Secret-Passw0rd!"

_TRIAD_CODE = """
import os

QUESTION = os.environ["SIM2REAL_QUESTION"]
ANSWER = os.environ["SIM2REAL_ANSWER"]


def handler(event, context):
    # One function implements all three CUSTOM_AUTH triggers, switching on triggerSource.
    # Define fails the authentication outright after a single wrong answer: exactly one
    # attempt, so the rejection below is unambiguous rather than a retry budget running out.
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CUSTOM_AUTH answer the VerifyAuthChallengeResponse trigger marks incorrect is refused with
    NotAuthorizedException, mints no token and leaves the user untouched, while the correct
    answer to the same challenge issues a token GetUser accepts."""
    cog = ctx.client("cognito-idp")
    trigger = _create_lambda(
        ctx, _TRIAD_CODE, env={"SIM2REAL_QUESTION": QUESTION, "SIM2REAL_ANSWER": ANSWER}
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
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    def _start_custom_auth():
        init = _retry_on_lambda_warmup(
            lambda: cog.initiate_auth(
                ClientId=client_id, AuthFlow="CUSTOM_AUTH",
                AuthParameters={"USERNAME": username},
            )
        )
        assert init["ChallengeName"] == "CUSTOM_CHALLENGE", (
            f"the Define trigger did not drive a custom challenge: {init!r}"
        )
        return init

    # --- the one broken thing: a wrong answer to a correctly configured challenge ---
    wrong_init = _start_custom_auth()
    error_payload = _rejection_response(
        lambda: cog.respond_to_auth_challenge(
            ClientId=client_id, ChallengeName="CUSTOM_CHALLENGE", Session=wrong_init["Session"],
            ChallengeResponses={"USERNAME": username, "ANSWER": WRONG_ANSWER},
        )
    )
    code = error_payload["Error"]["Code"]
    assert code == "NotAuthorizedException", (
        f"a wrong custom-auth answer was not refused with the exact code: {code!r} "
        f"(full payload {error_payload!r})"
    )
    message = error_payload["Error"]["Message"]
    assert message == "Incorrect username or password.", (
        f"a wrong custom-auth answer was refused with an unexpected message: {message!r}"
    )
    # (b) the effect is absent: no token accompanied the refusal, and the user is unchanged.
    assert "AuthenticationResult" not in error_payload, (
        f"tokens accompanied the rejection: {sorted(error_payload)!r}"
    )
    after = cog.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "CONFIRMED" and after["Enabled"] is True, (
        f"the refused attempt mutated the user: UserStatus={after['UserStatus']!r} "
        f"Enabled={after['Enabled']!r}"
    )

    # --- (c) positive control: the same challenge, answered correctly, in the same file ---
    control_init = _start_custom_auth()
    control = cog.respond_to_auth_challenge(
        ClientId=client_id, ChallengeName="CUSTOM_CHALLENGE", Session=control_init["Session"],
        ChallengeResponses={"USERNAME": username, "ANSWER": ANSWER},
    )
    control_token = control.get("AuthenticationResult", {}).get("AccessToken")
    assert control_token, (
        f"the correct answer did not issue a token, so the refusal above is not specific: "
        f"{control!r}"
    )
    who = cog.get_user(AccessToken=control_token)
    assert who["Username"] == username, (
        f"the control token is not usable against GetUser: {who!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _rejection_response(fn) -> dict:
    """Return the full botocore error response of a call expected to be REJECTED.

    Raises when the call SUCCEEDS instead of returning a falsy sentinel: a target accepting
    input real AWS rejects must never be reported as an error-code mismatch."""
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
    # No unconditional wait here: IAM role trust propagation is fully absorbed by the bounded
    # "cannot be assumed" / "InvalidParameterValue" retry in _create_function_with_retry below,
    # which already has its own deadline and stated reason.
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
            # Registered BEFORE the function's own teardown, so LIFO runs it LAST, and it POLLS.
            # Lambda creates /aws/lambda/<name> lazily, AFTER the invocation returns, so a
            # one-shot delete loses the race and the group materialises seconds later.
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
