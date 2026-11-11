"""lambda-describe-rest-apis-via-sdk-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-describe-rest-apis-via-sdk-positive"
GROUP = "sdk-call"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_HANDLER_SRC = """
import json
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("apigateway")
    target_id = event["target_id"]
    try:
        ids = []
        position = None
        found = False
        for _ in range(50):
            kwargs = {"limit": 500}
            if position:
                kwargs["position"] = position
            resp = client.get_rest_apis(**kwargs)
            for item in resp.get("items", []):
                ids.append(item["id"])
                if item["id"] == target_id:
                    found = True
            position = resp.get("position")
            if not position:
                break
        return {"ok": True, "found": found, "count": len(ids)}
    except ClientError as exc:
        return {"ok": False, "error_code": exc.response["Error"]["Code"]}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function calling apigateway.get_rest_apis via boto3 lists a real REST API."""
    apigw = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-behav-restapi-")
    api = apigw.create_rest_api(name=api_name, tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    role_name, role_arn = _create_lambda_role(
        ctx,
        statements=[{"Effect": "Allow", "Action": "apigateway:GET", "Resource": "*"}],
    )

    fn_name = ctx.unique_name("sim2real-behav-fn-")
    _create_function(ctx, fn_name, role_arn, _zip_from_source(_HANDLER_SRC))

    result = _invoke(ctx, fn_name, {"target_id": api_id})
    assert result["ok"] is True, f"unexpected failure: {result}"
    assert result["found"] is True, f"created REST API {api_id} not present in get_rest_apis listing: {result}"


# ===== helpers =====
def _zip_from_source(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements=None, policy_name: str = "inline-policy"):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_name, role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(ctx, name: str, role_arn: str, code: bytes, env=None, timeout: int = 20) -> str:
    lam = ctx.client("lambda")
    resp = None
    # A new role is not assumable by Lambda until IAM propagates it: retry that error to 60 s.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while resp is None:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real": name},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"lambda create_function never succeeded (role propagation?): {exc}") from exc
            time.sleep(2)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=name)["State"]
        if state == "Active":
            return resp["FunctionArn"]
        time.sleep(2)
    raise AssertionError("lambda function never became Active")


def _invoke(ctx, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invoke raised unhandled error: {body}")
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
