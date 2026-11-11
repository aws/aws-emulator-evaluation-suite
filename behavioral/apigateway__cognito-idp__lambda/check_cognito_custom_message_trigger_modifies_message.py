"""cognito-custom-message-trigger-modifies-message."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cognito-custom-message-trigger-modifies-message"
GROUP = "data-format"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CustomMessage trigger returning the event with a modified emailMessage lets SignUp complete, while one
    returning no `response` object makes SignUp fail with InvalidLambdaResponseException (the user stays UNCONFIRMED)."""
    role_arn = _create_lambda_role(ctx)

    # Positive: valid-length custom message embedding the codeParameter placeholder.
    ok_code = (
        "def handler(event, context):\n"
        "    if event.get('triggerSource') == 'CustomMessage_SignUp':\n"
        "        code = event['request']['codeParameter']\n"
        "        event['response']['emailMessage'] = f'Sim2Real verification code: {code}'\n"
        "        event['response']['emailSubject'] = 'Sim2Real verification'\n"
        "    return event\n"
    )
    fn_name, fn_arn = _create_lambda_function(ctx, role_arn, ok_code)
    pool_id, pool_arn = _create_user_pool(
        ctx,
        lambda_config={"CustomMessage": fn_arn},
        AutoVerifiedAttributes=["email"],
    )
    _grant_cognito_invoke(ctx, fn_name, pool_arn)
    client_id = _create_pool_client(ctx, pool_id)

    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    resp = idp.sign_up(
        ClientId=client_id,
        Username=username,
        Password="Sim2Real!Passw0rd",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    assert resp["UserConfirmed"] is False, (
        f"expected UserConfirmed=False on sign_up, got {resp['UserConfirmed']!r}"
    )
    user = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user["UserStatus"] == "UNCONFIRMED", (
        f"expected UserStatus=UNCONFIRMED after sign_up, got {user['UserStatus']!r}"
    )

    # Negative: sibling pool whose trigger returns a payload missing the expected
    # `response` object entirely. SignUp must be rejected and leave no user.
    malformed_code = (
        "def handler(event, context):\n"
        "    return {'unexpected': 'shape', 'noResponseKey': True}\n"
    )
    ctrl_fn_name, ctrl_fn_arn = _create_lambda_function(ctx, role_arn, malformed_code)
    ctrl_pool_id, ctrl_pool_arn = _create_user_pool(
        ctx,
        lambda_config={"CustomMessage": ctrl_fn_arn},
        AutoVerifiedAttributes=["email"],
    )
    _grant_cognito_invoke(ctx, ctrl_fn_name, ctrl_pool_arn)
    ctrl_client_id = _create_pool_client(ctx, ctrl_pool_id)
    ctrl_username = ctx.unique_name("sim2real-user-ctrl-")

    code, message = _client_error(
        lambda: idp.sign_up(
            ClientId=ctrl_client_id,
            Username=ctrl_username,
            Password="Sim2Real!Passw0rd",
            UserAttributes=[{"Name": "email", "Value": f"{ctrl_username}@example.com"}],
        )
    )
    assert code == "InvalidLambdaResponseException", (
        f"expected InvalidLambdaResponseException for a CustomMessage trigger returning "
        f"a payload with no `response` key, got {code!r}"
    )
    expected_message = "Unrecognizable lambda output"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    # The user record itself is NOT rolled back -- SignUp persists the user before
    # invoking CustomMessage to format the delivery; only the message-formatting step
    # failed, surfaced back to the caller.
    ctrl_user = idp.admin_get_user(UserPoolId=ctrl_pool_id, Username=ctrl_username)
    assert ctrl_user["UserStatus"] == "UNCONFIRMED", (
        f"expected the sign_up-created user to persist as UNCONFIRMED despite the "
        f"CustomMessage rejection, got {ctrl_user['UserStatus']!r}"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true"}


def _resource_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _zip_code(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cog-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=_resource_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )
    return role_arn


def _create_lambda_function(
    ctx, role_arn: str, code: str, env: dict[str, str] | None = None
) -> tuple[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cog-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_code(code)},
        Timeout=15,
        Publish=True,
        Tags=_resource_tags(),
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    fn_arn = None
    last_err: Exception | None = None
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            fn_arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # Bounded retry for IAM role propagation delay, not a fixed sleep.
            last_err = exc
            time.sleep(5)
    if fn_arn is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {name} Active",
    )
    return name, fn_arn


def _grant_cognito_invoke(ctx, function_name: str, source_arn: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId="cognito-invoke",
        Action="lambda:InvokeFunction",
        Principal="cognito-idp.amazonaws.com",
        SourceArn=source_arn,
    )


def _create_user_pool(
    ctx, lambda_config: dict[str, Any] | None = None, **extra
) -> tuple[str, str]:
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-cog-pool-")
    kwargs: dict[str, Any] = {"PoolName": name, "UserPoolTags": _resource_tags()}
    if lambda_config:
        kwargs["LambdaConfig"] = lambda_config
    kwargs.update(extra)
    pool = idp.create_user_pool(**kwargs)["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id, pool["Arn"]


def _create_pool_client(
    ctx, pool_id: str, explicit_auth_flows: list[str] | None = None
) -> str:
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-cog-client-")
    flows = explicit_auth_flows or [
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_CUSTOM_AUTH",
    ]
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=name,
        ExplicitAuthFlows=flows,
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    )
    return client_id


def _client_error(fn) -> tuple:
    """Call fn, which AWS must refuse, and return the (code, message) of its ClientError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
