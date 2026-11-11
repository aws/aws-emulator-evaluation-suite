"""lambda-secretsmanager-iam-missing-permission-rejected."""
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

CHECK = "lambda-secretsmanager-iam-missing-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER = textwrap.dedent(
    """
    import boto3
    from botocore.exceptions import ClientError

    def handler(event, context):
        client = boto3.client("secretsmanager")
        try:
            resp = client.get_secret_value(SecretId=event["secret_id"])
            return {"ok": True, "secret_string": resp["SecretString"]}
        except ClientError as exc:
            return {"ok": False, "error_code": exc.response["Error"]["Code"]}
    """
)


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role with zero secretsmanager permissions (implicit deny, no resource policy
    involved) cannot call GetSecretValue; granting the permission afterward (positive control,
    same role/function) makes the identical call succeed."""
    secrets = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-secret-")
    secret_value = f"payload-{uuid.uuid4()}"
    created = secrets.create_secret(
        Name=secret_name,
        SecretString=secret_value,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: secrets.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    # No secretsmanager statements at all -- only the basic-execution managed policy.
    role_name, role_arn = _create_lambda_role_no_statements(ctx)
    func_name = _create_lambda_function(ctx, role_arn, _HANDLER)

    denied = _invoke(ctx, func_name, {"secret_id": secret_arn})
    assert denied["ok"] is False, f"expected the fetch to be denied with zero secretsmanager permissions, got {denied!r}"
    assert denied["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException with no secretsmanager permissions, got {denied!r}"
    )
    assert "secret_string" not in denied, f"secret value must not leak on a denied fetch, got {denied!r}"

    # Positive control: grant the missing permission on the same role, then retry.
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline-secretsmanager-added",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": secret_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-secretsmanager-added")
    )

    def _probe_allowed():
        return _invoke(ctx, func_name, {"secret_id": secret_arn})

    allowed = _poll_until(_probe_allowed, lambda b: b["ok"] is True, timeout_s=30.0, interval_s=3.0)
    assert allowed["ok"] is True, f"expected the identical call to succeed once the permission was granted, got {allowed!r}"
    assert allowed["secret_string"] == secret_value, (
        f"expected the exact secret value back, got {allowed.get('secret_string')!r}"
    )


_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_BASIC_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _create_lambda_role_no_statements(ctx) -> tuple[str, str]:
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
    return role_name, role_arn


def _build_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


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


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


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
