"""cognito-pre-token-v2-trigger-group-override."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cognito-pre-token-v2-trigger-group-override"
GROUP = "trigger-delivery"
SERVICES = ["apigateway", "cognito-idp", "lambda"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true"}


def _resource_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PreTokenGeneration V2_0 trigger's claimsAndScopeOverrideDetails.groupOverrideDetails
    replaces the cognito:groups claim that Cognito bakes into the issued ID token."""
    role_arn = _create_lambda_role(ctx)
    code = (
        "def handler(event, context):\n"
        "    if event.get('triggerSource', '').startswith('TokenGeneration'):\n"
        "        event['response'] = {\n"
        "            'claimsAndScopeOverrideDetails': {\n"
        "                'groupOverrideDetails': {\n"
        "                    'groupsToOverride': ['sim2real-override-group']\n"
        "                }\n"
        "            }\n"
        "        }\n"
        "    return event\n"
    )
    fn_name, fn_arn = _create_lambda_function(ctx, role_arn, code)
    pool_id, pool_arn = _create_user_pool(
        ctx,
        lambda_config={
            "PreTokenGenerationConfig": {"LambdaArn": fn_arn, "LambdaVersion": "V2_0"}
        },
        UserPoolTier="ESSENTIALS",
    )
    _grant_cognito_invoke(ctx, fn_name, pool_arn)
    client_id = _create_pool_client(
        ctx, pool_id, explicit_auth_flows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"]
    )

    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id,
        Username=username,
        Password="Sim2Real!Passw0rd",
        Permanent=True,
    )

    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": "Sim2Real!Passw0rd"},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    claims = _decode_jwt_payload(id_token)
    assert claims.get("cognito:groups") == ["sim2real-override-group"], (
        f"expected cognito:groups == ['sim2real-override-group'] from the V2_0 "
        f"groupOverrideDetails, got {claims.get('cognito:groups')!r}"
    )


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
            fn_arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
    if fn_arn is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")
    # Registered BEFORE the function's own teardown, so LIFO runs it LAST, and it POLLS:
    # Lambda creates /aws/lambda/<name> lazily, after the trigger invocation returns, so a
    # one-shot delete issued right after create_function loses that race almost every time.
    ctx.on_cleanup(lambda: _delete_log_group_when_it_appears(ctx, name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {name} Active",
    )
    return name, fn_arn


def _delete_log_group_when_it_appears(ctx, fn_name: str, timeout_s: float = 45.0) -> None:
    """Delete /aws/lambda/<fn_name>, waiting for the group to exist first.

    The group is created by the Lambda SERVICE, asynchronously, so a delete issued the
    instant a check ends races it and loses. Polling the delete itself -- rather than
    sleeping -- makes the teardown converge on the observable condition. Never raises:
    on_cleanup swallows exceptions, so a failure here must be printed to be visible at all.
    """
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


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
