"""rotate-secret-without-lambda-arn-configured-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotate-secret-without-lambda-arn-configured-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]

_LAMBDA_CODE = """
def handler(event, context):
    return {"ok": True}
"""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateSecret fails when no rotation Lambda was ever configured and none is supplied, instead of no-oping."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secmgr-norot-")
    created = sm.create_secret(
        Name=name, SecretString="norotation-value", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    original_version = created["VersionId"]

    code, message = _error_code(lambda: sm.rotate_secret(SecretId=secret_arn))
    assert code == "InvalidRequestException", f"unexpected rotate-without-lambda code: {code!r}"
    assert message == "No Lambda rotation function ARN is associated with this secret.", (
        f"unexpected rotate-without-lambda message: {message!r}"
    )

    # Effect absent: no rotation was silently kicked off -- still exactly one version, AWSCURRENT unmoved.
    after = sm.describe_secret(SecretId=secret_arn)
    assert after.get("RotationEnabled", False) is False
    stages = after["VersionIdsToStages"]
    assert "AWSCURRENT" in stages.get(original_version, [])
    assert len(stages) == 1

    # Positive control: supplying a real, existing rotation Lambda ARN makes the same call succeed.
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-behav-secmgr-norot-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    func_name = ctx.unique_name("sim2real-behav-secmgr-norot-fn-")
    func_arn = _create_function_with_retry(lam, func_name, role_arn, _zip_bytes(_LAMBDA_CODE), tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))

    lam.add_permission(
        FunctionName=func_name,
        StatementId="allow-secretsmanager-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
    )

    # This must NOT raise -- the only thing that changed is the presence of RotationLambdaARN.
    # Lambda permission/role propagation can lag briefly, so retry the call to a bounded deadline
    # rather than treating a transient "Lambda validation failed" as a hard failure.
    _rotate_with_retry(sm, secret_arn, func_arn, timeout_s=60.0)
    final_desc = sm.describe_secret(SecretId=secret_arn)
    assert final_desc.get("RotationLambdaARN") == func_arn


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _rotate_with_retry(sm, secret_arn: str, func_arn: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            sm.rotate_secret(
                SecretId=secret_arn, RotationLambdaARN=func_arn, RotationRules={"AutomaticallyAfterDays": 1}
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"rotate_secret with a real Lambda ARN never succeeded (propagation?): {last_exc}")


def _zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_function_with_retry(
    lam, func_name: str, role_arn: str, code_bytes: bytes, tags: dict[str, str], timeout_s: float = 90.0
) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code_bytes},
                Timeout=15,
                Tags=tags,
            )
            return resp["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
