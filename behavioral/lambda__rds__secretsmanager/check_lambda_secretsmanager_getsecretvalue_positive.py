"""lambda-secretsmanager-getsecretvalue-positive."""
from __future__ import annotations

import io
import json
import textwrap
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-secretsmanager-getsecretvalue-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER = textwrap.dedent(
    """
    import boto3

    def handler(event, context):
        client = boto3.client("secretsmanager")
        resp = client.get_secret_value(SecretId=event["secret_id"])
        return {"secret_string": resp["SecretString"], "version_id": resp["VersionId"]}
    """
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function with a scoped IAM allow retrieves a secret's value end-to-end."""
    secrets = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-secret-")
    expected_value = f"payload-{uuid.uuid4()}"
    created = secrets.create_secret(
        Name=secret_name,
        SecretString=expected_value,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: secrets.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": secret_arn,
            }
        ],
    )
    func_name = _create_lambda_function(ctx, role_arn, _HANDLER)

    body = _invoke(ctx, func_name, {"secret_id": secret_arn})

    assert body["secret_string"] == expected_value, (
        f"lambda-retrieved secret value mismatch: expected {expected_value!r}, got {body['secret_string']!r}"
    )

    versions = secrets.list_secret_version_ids(SecretId=secret_arn)["Versions"]
    current = [v for v in versions if "AWSCURRENT" in v.get("VersionStages", [])]
    assert len(current) == 1, f"expected exactly one AWSCURRENT version, found {len(current)}: {versions}"
    assert body["version_id"] == current[0]["VersionId"], (
        f"lambda-reported version id {body['version_id']!r} != AWSCURRENT version id "
        f"{current[0]['VersionId']!r} from an independent list_secret_version_ids read"
    )


_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_BASIC_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _build_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST_POLICY),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY_ARN))
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline-secretsmanager",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-secretsmanager"))
    return role_arn


def _create_lambda_function(ctx, role_arn: str, handler_code: str) -> str:
    lam = ctx.client("lambda")
    func_name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _build_zip(handler_code)
    deadline = time.monotonic() + 60.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Tags={"sim2real-check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2.0)
    else:
        raise AssertionError(f"lambda function never became creatable (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_for_function_active(ctx, func_name)
    return func_name


def _wait_for_function_active(ctx, func_name: str, timeout_s: float = 60.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=func_name)["State"]
        if state == "Active":
            return
        time.sleep(2.0)
    raise AssertionError(f"lambda function never became Active, last state={state}")


def _invoke(ctx, func_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=func_name, Payload=json.dumps(payload).encode("utf-8"))
    raw = resp["Payload"].read()
    body = json.loads(raw) if raw else {}
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored ({resp['FunctionError']}): {body}")
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
