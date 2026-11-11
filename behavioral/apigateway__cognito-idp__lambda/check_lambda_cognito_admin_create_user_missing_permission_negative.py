"""lambda-cognito-admin-create-user-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-cognito-admin-create-user-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cognito-idp", "lambda"]

_HANDLER_SRC = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("cognito-idp")
    try:
        resp = client.admin_create_user(
            UserPoolId=event["user_pool_id"],
            Username=event["username"],
            MessageAction="SUPPRESS",
        )
        return {"ok": True, "username": resp["User"]["Username"]}
    except ClientError as e:
        return {"ok": False, "code": e.response["Error"]["Code"], "message": e.response["Error"]["Message"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda role lacking cognito-idp:AdminCreateUser gets AccessDeniedException and creates no user;
    an identical Lambda whose role DOES grant the permission (positive control) succeeds."""
    pool_id = _create_user_pool(ctx)
    cognito = ctx.client("cognito-idp")

    # Negative: role has no cognito-idp permissions at all.
    denied_role_arn = _create_lambda_role(ctx, [])
    denied_fn = _create_lambda_function(ctx, denied_role_arn, _HANDLER_SRC)
    denied_username = ctx.unique_name("sim2real-denied-user-")
    denied_result = _invoke_lambda(ctx, denied_fn, {"user_pool_id": pool_id, "username": denied_username})

    assert denied_result["ok"] is False, f"expected denial, got: {denied_result}"
    assert denied_result["code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got: {denied_result}"
    )
    denied_role_name = denied_role_arn.rsplit("/", 1)[1]
    pool_arn = f"arn:aws:cognito-idp:{ctx.region}:{ctx.account}:userpool/{pool_id}"
    expected_denied_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{denied_role_name}/{denied_fn} "
        f"is not authorized to perform: cognito-idp:AdminCreateUser on resource: {pool_arn} "
        f"because no identity-based policy allows the cognito-idp:AdminCreateUser action"
    )
    assert denied_result["message"] == expected_denied_message, (
        f"expected message {expected_denied_message!r}, got {denied_result['message']!r}"
    )

    def _get_denied_user():
        return cognito.admin_get_user(UserPoolId=pool_id, Username=denied_username)

    denied_lookup_code, denied_lookup_message = _client_error(_get_denied_user)
    assert denied_lookup_code == "UserNotFoundException", (
        f"expected UserNotFoundException confirming the denied create left no user behind, "
        f"got: {denied_lookup_code}"
    )
    assert denied_lookup_message == "User does not exist.", (
        f"expected message 'User does not exist.', got {denied_lookup_message!r}"
    )

    # Positive control: identical setup, but the role grants the permission.
    allowed_role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": "cognito-idp:AdminCreateUser",
                "Resource": f"arn:aws:cognito-idp:{ctx.region}:*:userpool/{pool_id}",
            }
        ],
    )
    allowed_fn = _create_lambda_function(ctx, allowed_role_arn, _HANDLER_SRC)
    allowed_username = ctx.unique_name("sim2real-allowed-user-")
    allowed_result = _invoke_lambda(ctx, allowed_fn, {"user_pool_id": pool_id, "username": allowed_username})

    assert allowed_result["ok"] is True, f"positive control failed: {allowed_result}"
    got = cognito.admin_get_user(UserPoolId=pool_id, Username=allowed_username)
    assert got["Username"] == allowed_username, (
        f"expected admin_get_user to report {allowed_username!r}, got {got.get('Username')!r}"
    )
    cognito.admin_delete_user(UserPoolId=pool_id, Username=allowed_username)


_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _client_error(fn):
    """The captured AWS error (code, message). An unexpected SUCCESS raises rather than returning a
    falsy sentinel: a denied create that nonetheless left a readable user is the exact failure this
    check exists to catch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the lookup to fail with UserNotFoundException, but it SUCCEEDED: {result!r}"
    )


def _create_user_pool(ctx: Any, **kwargs: Any) -> str:
    cognito = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    pool = cognito.create_user_pool(
        PoolName=name, UserPoolTags={"sim2real": CHECK}, **kwargs
    )["UserPool"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool["Id"]))
    return pool["Id"]


def _create_lambda_role(ctx: Any, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if statements:
        policy_name = ctx.unique_name("sim2real-policy-")
        iam.put_role_policy(
            RoleName=name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return role["Arn"]


def _zip_code(handler_source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_source)
    return buf.getvalue()


def _create_lambda_function(ctx: Any, role_arn: str, handler_source: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _zip_code(handler_source)
    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"lambda role never became assumable: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    active_deadline = time.monotonic() + 60
    state = None
    while time.monotonic() < active_deadline:
        state = lam.get_function_configuration(FunctionName=name)["State"]
        if state == "Active":
            break
        time.sleep(2)
    if state != "Active":
        raise AssertionError(f"lambda function never became Active, last state: {state}")
    return name


def _invoke_lambda(ctx: Any, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised FunctionError: {body}")
    return body


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
