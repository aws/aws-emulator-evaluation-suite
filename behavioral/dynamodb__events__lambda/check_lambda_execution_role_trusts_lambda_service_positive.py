"""lambda-execution-role-trusts-lambda-service-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-execution-role-trusts-lambda-service-positive"
GROUP = "iam-trust"
SERVICES = ["dynamodb", "events", "lambda"]

_HANDLER_STS = """
import boto3

def handler(event, context):
    sts = boto3.client("sts")
    ident = sts.get_caller_identity()
    return {"arn": ident["Arn"]}
"""


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function whose role trusts lambda.amazonaws.com runs without error and its sts:GetCallerIdentity returns an
    assumed-role ARN of that role: Lambda assumed the execution role.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lambda-trust-ok-")
    role_arn = _create_role(ctx, iam, role_name, "lambda.amazonaws.com")
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )

    func_name = ctx.unique_name("sim2real-lambda-trust-ok-fn-")
    code = _zip_lambda_code(_HANDLER_STS)
    _create_function_with_retry(
        lam,
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": code},
        Timeout=15,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))

    _wait_active(lam, func_name)

    invoke_resp = lam.invoke(FunctionName=func_name, InvocationType="RequestResponse")
    assert invoke_resp["StatusCode"] == 200, f"expected StatusCode 200, got {invoke_resp!r}"
    assert "FunctionError" not in invoke_resp, f"invocation errored: {invoke_resp!r}"
    payload = json.loads(invoke_resp["Payload"].read())
    assert ":assumed-role/" in payload["arn"], payload
    assert f"assumed-role/{role_name}/" in payload["arn"], payload


def _trust_policy(principal_service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": principal_service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_role(ctx, iam, role_name: str, principal_service: str) -> str:
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy(principal_service),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        try:
            for pol in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            for pol in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _zip_lambda_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()


def _create_function_with_retry(
    lam, *, timeout_s: float = 90.0, interval_s: float = 3.0, **kwargs: Any
):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever calling create_function"
    raise last_exc


def _wait_active(lam, func_name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=func_name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"function {func_name} never became Active")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
