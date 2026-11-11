"""lambda-apigateway-wrong-api-id-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-apigateway-wrong-api-id-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

HANDLER_CODE = """
import boto3

def handler(event, context):
    client = boto3.client("apigateway")
    try:
        resp = client.get_rest_api(restApiId=event["restApiId"])
        return {"success": True, "id": resp["id"], "name": resp.get("name")}
    except Exception as e:
        error = getattr(e, "response", {}).get("Error", {})
        return {"success": False, "code": error.get("Code"), "message": error.get("Message")}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda allowed apigateway:GET gets NotFoundException from GetRestApi for a nonexistent id, while
    the same call with the real id succeeds before and after the rejected call."""
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-restapi-")
    api = apigw.create_rest_api(name=api_name, tags={"sim2real:managed": "true"})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": "apigateway:GET", "Resource": "*"}]
    )
    fn_name = _create_lambda_function(ctx, role_arn, HANDLER_CODE)

    good_payload = _invoke(ctx, fn_name, {"restApiId": api_id})
    assert good_payload["success"] is True, good_payload
    assert good_payload["id"] == api_id, good_payload

    bogus_id = "z" + api_id[1:] if api_id[0] != "z" else "y" + api_id[1:]
    bad_payload = _invoke(ctx, fn_name, {"restApiId": bogus_id})
    assert bad_payload["success"] is False, bad_payload
    assert bad_payload["code"] == "NotFoundException", bad_payload
    assert bad_payload["message"] == f"Invalid API identifier specified {ctx.account}:{bogus_id}", bad_payload

    restored_payload = _invoke(ctx, fn_name, {"restApiId": api_id})
    assert restored_payload["success"] is True, restored_payload
    assert restored_payload["id"] == api_id, restored_payload


def _zip_code(filename: str, code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_arn))
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-lam-pol-")
        doc = {"Version": "2012-10-17", "Statement": policy_statements}
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lam-fn-")
    zip_bytes = _zip_code("index.py", code)
    last_err = None
    for _ in range(15):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
            continue
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return name


def _wait_for_active(ctx, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda {name} never became Active")


def _invoke(ctx, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invoke error: {body}")
    return body


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
