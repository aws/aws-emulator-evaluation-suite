"""iam-role-trust-lambda-service-assume."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-trust-lambda-service-assume"
GROUP = "trust-policy"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose trust policy names lambda.amazonaws.com lets Lambda actually
    assume it: CreateFunction succeeds and Invoke runs the handler end to end,
    proving the AssumeRole (not just that IAM accepted the JSON)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-lambda-role-")
    trust_doc = _trust_doc(["lambda.amazonaws.com"])
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"))

    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-lambda-fn-")
    code = _lambda_zip(
        "def handler(event, context):\n"
        "    return {'doubled': event.get('value', 0) * 2}\n"
    )
    fn_arn = _create_function_with_retry(ctx, lam, role_arn, fn_name, code)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    assert fn_arn, "CreateFunction returned no FunctionArn"

    _wait_function_active(lam, fn_name)

    resp = lam.invoke(
        FunctionName=fn_name,
        Payload=json.dumps({"value": 21}).encode("utf-8"),
    )
    assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"unexpected FunctionError: {resp.get('FunctionError')}"
    payload = json.loads(resp["Payload"].read())
    assert payload == {"doubled": 42}, f"unexpected invoke result: {payload}"


def _trust_doc(services: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": services},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_function_with_retry(
    ctx, lam, role_arn: str, fn_name: str, code_bytes: bytes, timeout_s: float = 60.0
) -> str:
    """IAM role propagation is eventually consistent; retry CreateFunction while
    Lambda reports it cannot yet assume the freshly created role."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_bytes},
                Timeout=15,
            )
            return resp["FunctionArn"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if (
                code == "InvalidParameterValueException"
                and "cannot be assumed" in msg
                and time.monotonic() < deadline
            ):
                time.sleep(3)
                continue
            raise
    raise AssertionError("CreateFunction never succeeded")


def _wait_function_active(lam, fn_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError("function never became Active")


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
