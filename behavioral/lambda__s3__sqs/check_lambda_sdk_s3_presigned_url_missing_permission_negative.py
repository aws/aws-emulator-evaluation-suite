"""lambda-sdk-s3-presigned-url-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-s3-presigned-url-missing-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]

_HANDLER_CODE = """
import boto3

def handler(event, context):
    s3 = boto3.client("s3")
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": event["bucket"], "Key": event["key"]},
        ExpiresIn=300,
    )
    return {"url": url}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Lambda role lacking s3:GetObject can still sign a presigned URL (signing is local),
    but S3 denies fetching it; the same function with s3:GetObject fetches it (positive control)."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-presignperm-")
    _create_bucket(ctx, bucket)
    key = "presigned/object.bin"
    body = b"presigned-permission-fixture-payload"
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    # No S3 statements at all — only the Lambda basic-execution policy (logs only).
    unauthorized_role_arn = _create_lambda_role(ctx, [])
    unauthorized_fn = _create_lambda_function(ctx, unauthorized_role_arn, _HANDLER_CODE)

    unauthorized_result = _invoke_lambda(ctx, unauthorized_fn, {"bucket": bucket, "key": key})
    unauthorized_url = unauthorized_result["url"]
    assert not (p := ctx.published_url_mismatch(unauthorized_url)), p

    try:
        _url, _route = ctx.endpoint_route(unauthorized_url)
        with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=15) as resp:
            resp.read()
        raise AssertionError("expected fetching the presigned URL to be denied (AccessDenied), but it succeeded")
    except urllib.error.HTTPError as err:
        err_body = err.read() if hasattr(err, "read") else b""
        assert err.code == 403, f"expected HTTP 403 (AccessDenied) for the unauthorized presigned URL, got {err.code}"
        assert b"AccessDenied" in err_body, f"expected AccessDenied in the S3 error body, got {err_body[:200]!r}"

    # Positive control: identical function/object, backed by a role WITH s3:GetObject.
    authorized_role_arn = _create_lambda_role(
        ctx,
        [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"}],
    )
    authorized_fn = _create_lambda_function(ctx, authorized_role_arn, _HANDLER_CODE)
    authorized_result = _invoke_lambda(ctx, authorized_fn, {"bucket": bucket, "key": key})
    authorized_url = authorized_result["url"]

    _url, _route = ctx.endpoint_route(authorized_url)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=15) as resp:
        fetched = resp.read()
        status = resp.status
    assert status == 200, f"positive control: expected 200 from presigned URL fetch, got {status}"
    assert fetched == body, f"positive control: expected {body!r}, got {fetched!r}"




# ===== helpers =====
_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; every other
    # region requires it. Not a region pin -- this check still runs at ctx.region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    if statements:
        policy_name = ctx.unique_name("sim2real-behav-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn



def _create_lambda_function(ctx, role_arn: str, code: str, env: dict[str, str] | None = None, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_code(code)},
        Timeout=timeout,
        Publish=True,
        Tags={"sim2real": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    last_err: Exception | None = None
    ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
    # A new execution role is not assumable by Lambda at once: retry its InvalidParameterValue to a deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while time.monotonic() < deadline:
        try:
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(2)
    else:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke_lambda(ctx, fn_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=fn_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
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
