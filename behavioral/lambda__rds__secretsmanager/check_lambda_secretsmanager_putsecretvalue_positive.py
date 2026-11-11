"""lambda-secretsmanager-putsecretvalue-positive."""
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

CHECK = "lambda-secretsmanager-putsecretvalue-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER = textwrap.dedent(
    """
    import boto3

    def handler(event, context):
        client = boto3.client("secretsmanager")
        resp = client.put_secret_value(
            SecretId=event["secret_id"],
            SecretString=event["new_value"],
            ClientRequestToken=event["token"],
        )
        return {"version_id": resp["VersionId"], "stages": resp["VersionStages"]}
    """
)


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function updates a secret; the new value is observable on the next GetSecretValue
    and the prior value survives as AWSPREVIOUS."""
    secrets = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-secret-")
    initial_value = f"initial-{uuid.uuid4()}"
    created = secrets.create_secret(
        Name=secret_name, SecretString=initial_value, Tags=[{"Key": "sim2real", "Value": "true"}]
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: secrets.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    # The function only needs write access -- it never reads the value back itself.
    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:PutSecretValue",
                "Resource": secret_arn,
            }
        ],
    )
    func_name = _create_lambda_function(ctx, role_arn, _HANDLER)

    updated_value = f"updated-{uuid.uuid4()}"
    body = _invoke(
        ctx,
        func_name,
        {"secret_id": secret_arn, "new_value": updated_value, "token": str(uuid.uuid4())},
    )
    assert "AWSCURRENT" in body["stages"], f"expected AWSCURRENT in stages, got {body['stages']}"

    current = secrets.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")
    assert current["SecretString"] == updated_value, (
        f"expected AWSCURRENT secret string {updated_value!r}, got {current['SecretString']!r}"
    )
    assert current["VersionId"] == body["version_id"], (
        f"expected AWSCURRENT version id {body['version_id']!r} (from the Lambda's PutSecretValue "
        f"response), got {current['VersionId']!r}"
    )

    previous = secrets.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")
    assert previous["SecretString"] == initial_value, (
        f"expected AWSPREVIOUS secret string {initial_value!r}, got {previous['SecretString']!r}"
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
                Tags={"sim2real": "true"},
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
