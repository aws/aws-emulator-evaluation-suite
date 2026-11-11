"""lambda-sesv2-tag-resource-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-tag-resource-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "sesv2"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function tags a sesv2 configuration set resource and reads the tag back via list_tags_for_resource."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    name = ctx.unique_name("sim2real-lsesv2-cfgset-")
    resource_arn = f"arn:aws:ses:{region}:{account_id}:configuration-set/{name}"

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["ses:CreateConfigurationSet", "ses:TagResource", "ses:ListTagsForResource"],
                "Resource": "*",
            }
        ],
    )
    handler_src = """
import boto3

def handler(event, context):
    client = boto3.client("sesv2")
    client.create_configuration_set(ConfigurationSetName=event["name"])
    client.tag_resource(
        ResourceArn=event["arn"],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    resp = client.list_tags_for_resource(ResourceArn=event["arn"])
    return {"tags": resp["Tags"]}
"""
    function_name = _create_function(ctx, role_arn, handler_src)
    ses = ctx.client("sesv2")

    def _cleanup_config_set() -> None:
        try:
            ses.delete_configuration_set(ConfigurationSetName=name)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_config_set)

    result = _invoke(ctx, function_name, {"name": name, "arn": resource_arn})
    assert result["function_error"] is None, f"lambda invocation raised: {result}"
    tags = {t["Key"]: t["Value"] for t in result["body"]["tags"]}
    assert tags.get("sim2real") == "true", f"expected tag sim2real=true in lambda's own read, got {tags}"

    # confirm it is durably persisted server-side, independent of the lambda's own read
    server_tags = {t["Key"]: t["Value"] for t in ses.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]}
    assert server_tags.get("sim2real") == "true", f"expected tag sim2real=true via independent read, got {server_tags}"


_PREFIX = "sim2real-lsesv2-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _lambda_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_lambda_role(ctx: Any, inline_statements: list[dict] | None = None) -> str:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_lambda_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    if inline_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline-perms",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )

    def _cleanup() -> None:
        if inline_statements:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName="inline-perms")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _zip_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_src)
    return buf.getvalue()


def _create_function(ctx: Any, role_arn: str, handler_src: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    code = _zip_code(handler_src)
    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except botocore.exceptions.ClientError as err:
            err_code = err.response["Error"]["Code"]
            if err_code == "InvalidParameterValueException" and "role" in str(err).lower():
                last_err = err
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"role never became assumable by Lambda: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke(ctx: Any, function_name: str, payload: dict | None = None) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    return {"function_error": resp.get("FunctionError"), "body": body}


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
