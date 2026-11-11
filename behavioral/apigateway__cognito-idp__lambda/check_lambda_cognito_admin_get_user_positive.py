"""lambda-cognito-admin-get-user-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-cognito-admin-get-user-positive"
GROUP = "sdk-call"
SERVICES = ["apigateway", "cognito-idp", "lambda"]

_HANDLER_SRC = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("cognito-idp")
    try:
        resp = client.admin_get_user(
            UserPoolId=event["user_pool_id"],
            Username=event["username"],
        )
        attrs = {a["Name"]: a["Value"] for a in resp.get("UserAttributes", [])}
        return {"ok": True, "username": resp["Username"], "status": resp["UserStatus"], "attrs": attrs}
    except ClientError as e:
        return {"ok": False, "code": e.response["Error"]["Code"], "message": e.response["Error"]["Message"]}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose role grants cognito-idp:AdminGetUser reads the real user attributes."""
    pool_id = _create_user_pool(ctx)
    cognito = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "name", "Value": "Behavioral Fidelity Tester"}],
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": "cognito-idp:AdminGetUser",
                "Resource": f"arn:aws:cognito-idp:{ctx.region}:*:userpool/{pool_id}",
            }
        ],
    )
    fn_name = _create_lambda_function(ctx, role_arn, _HANDLER_SRC)

    result = _invoke_lambda(ctx, fn_name, {"user_pool_id": pool_id, "username": username})

    assert result["ok"] is True, f"lambda-side call failed: {result}"
    assert result["username"] == username, f"expected username {username!r}, got {result.get('username')!r}"
    assert result["attrs"].get("name") == "Behavioral Fidelity Tester", (
        f"expected attribute name='Behavioral Fidelity Tester', got attrs={result['attrs']!r}"
    )


_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true"}


def _resource_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _create_user_pool(ctx: Any, **kwargs: Any) -> str:
    cognito = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    pool = cognito.create_user_pool(PoolName=name, UserPoolTags=_resource_tags(), **kwargs)["UserPool"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool["Id"]))
    return pool["Id"]


def _create_lambda_role(ctx: Any, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST_POLICY),
        Tags=_resource_tags_kv(),
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
                Tags=_resource_tags(),
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
