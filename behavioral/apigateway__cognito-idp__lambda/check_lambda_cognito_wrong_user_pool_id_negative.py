"""lambda-cognito-wrong-user-pool-id-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-cognito-wrong-user-pool-id-negative"
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda allowed cognito-idp:AdminCreateUser on any pool gets ResourceNotFoundException for a
    nonexistent UserPoolId and creates no user, while the same call on the real pool succeeds."""
    real_pool_id = _create_user_pool(ctx)
    cognito = ctx.client("cognito-idp")

    role_arn = _create_lambda_role(
        ctx,
        [{"Effect": "Allow", "Action": "cognito-idp:AdminCreateUser", "Resource": "*"}],
    )
    fn_name = _create_lambda_function(ctx, role_arn, _HANDLER_SRC)

    # Negative: same role/function, fabricated pool id in the same region/account shape.
    fake_pool_id = f"{ctx.region}_ffffffff9"
    fake_username = ctx.unique_name("sim2real-fake-user-")
    fake_result = _invoke_lambda(ctx, fn_name, {"user_pool_id": fake_pool_id, "username": fake_username})

    assert fake_result["ok"] is False, f"expected failure, got: {fake_result}"
    assert fake_result["code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on a fabricated pool id, got: {fake_result}"
    )
    expected_pool_message = f"User pool {fake_pool_id} does not exist."
    assert fake_result["message"] == expected_pool_message, (
        f"expected message {expected_pool_message!r}, got {fake_result['message']!r}"
    )

    # No user pool should exist under the fabricated id, and no user under the real pool either.
    def _get_from_fake_pool():
        cognito.admin_get_user(UserPoolId=fake_pool_id, Username=fake_username)

    fake_pool_code, fake_pool_message = _client_error(_get_from_fake_pool)
    assert fake_pool_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the fabricated pool, got: {fake_pool_code}"
    )
    assert fake_pool_message == expected_pool_message, (
        f"expected message {expected_pool_message!r}, got {fake_pool_message!r}"
    )

    def _get_from_real_pool():
        cognito.admin_get_user(UserPoolId=real_pool_id, Username=fake_username)

    real_pool_code, real_pool_message = _client_error(_get_from_real_pool)
    assert real_pool_code == "UserNotFoundException", (
        f"expected the fake username to be absent from the real pool too, got: {real_pool_code}"
    )
    assert real_pool_message == "User does not exist.", (
        f"expected message 'User does not exist.', got {real_pool_message!r}"
    )

    # Positive control: identical lambda/role, targeting the real pool, succeeds.
    real_username = ctx.unique_name("sim2real-real-user-")
    real_result = _invoke_lambda(ctx, fn_name, {"user_pool_id": real_pool_id, "username": real_username})
    assert real_result["ok"] is True, f"positive control failed: {real_result}"
    got = cognito.admin_get_user(UserPoolId=real_pool_id, Username=real_username)
    assert got["Username"] == real_username, f"expected {real_username}, got: {got['Username']}"

    # Prove the teardown too: after deleting the positive-control user, an independent read reports
    # it not-found, and the same admin_get_user that worked a moment ago fails specifically.
    cognito.admin_delete_user(UserPoolId=real_pool_id, Username=real_username)

    def _get_deleted_real_user():
        cognito.admin_get_user(UserPoolId=real_pool_id, Username=real_username)

    deleted_code, deleted_message = _client_error(_get_deleted_real_user)
    assert deleted_code == "UserNotFoundException", (
        f"expected UserNotFoundException reading the deleted user, got: {deleted_code}"
    )
    assert deleted_message == "User does not exist.", (
        f"expected message 'User does not exist.', got {deleted_message!r}"
    )


_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_MANAGED_TAG_KEY = "sim2real:managed"


def _managed_tags_kv() -> list:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]


def _client_error(fn):
    """Call fn, which AWS must refuse, and return the (code, message) of its ClientError."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_user_pool(ctx: Any, **kwargs: Any) -> str:
    cognito = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    pool = cognito.create_user_pool(
        PoolName=name, UserPoolTags={_MANAGED_TAG_KEY: "true"}, **kwargs
    )["UserPool"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool["Id"]))
    return pool["Id"]


def _create_lambda_role(ctx: Any, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST_POLICY),
        Tags=_managed_tags_kv(),
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
                Tags={_MANAGED_TAG_KEY: "true"},
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
