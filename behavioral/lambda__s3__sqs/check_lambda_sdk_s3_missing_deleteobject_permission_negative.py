"""lambda-sdk-s3-missing-deleteobject-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-s3-missing-deleteobject-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    s3 = boto3.client("s3")
    try:
        s3.delete_object(Bucket=event["bucket"], Key=event["key"])
        return {"status": "ok"}
    except ClientError as err:
        return {
            "status": "error",
            "code": err.response["Error"]["Code"],
            "message": err.response["Error"].get("Message"),
        }
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role lacking s3:DeleteObject gets AccessDenied and the object stays in the bucket;
    a role that DOES have the permission (positive control, same file) can delete it."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-deldenied-")
    _create_bucket(ctx, bucket)

    denied_key = "denied/object.txt"
    allowed_key = "allowed/object.txt"
    s3.put_object(Bucket=bucket, Key=denied_key, Body=b"stay-put")
    s3.put_object(Bucket=bucket, Key=allowed_key, Body=b"go-away")

    # Negative: role has read but explicitly no delete permission on the bucket.
    denied_role_arn = _create_lambda_role(
        ctx,
        [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"}],
    )
    denied_fn = _create_lambda_function(ctx, denied_role_arn, _HANDLER_CODE)
    denied_result = _invoke_lambda(ctx, denied_fn, {"bucket": bucket, "key": denied_key})
    assert denied_result["status"] == "error", (
        f"expected the delete to be refused (status=error), got status={denied_result['status']!r}"
    )
    assert denied_result["code"] == "AccessDenied", f"expected AccessDenied, got {denied_result['code']!r}"
    denied_role_name = denied_role_arn.rsplit("/", 1)[-1]
    expected_denied_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{denied_role_name}/{denied_fn} is not authorized "
        f'to perform: s3:DeleteObject on resource: "arn:aws:s3:::{bucket}/{denied_key}" because no '
        f"identity-based policy allows the s3:DeleteObject action"
    )
    assert denied_result["message"] == expected_denied_message, (
        f"expected AccessDenied message {expected_denied_message!r}, got {denied_result['message']!r}"
    )

    # Effect must be absent: the object is still there.
    head = s3.head_object(Bucket=bucket, Key=denied_key)
    assert head["ContentLength"] == len(b"stay-put"), (
        f"expected the refused delete to leave the object untouched "
        f"(ContentLength={len(b'stay-put')}), got ContentLength={head['ContentLength']!r}"
    )

    # Positive control: a role WITH s3:DeleteObject succeeds on a different key in the same bucket.
    allowed_role_arn = _create_lambda_role(
        ctx,
        [{"Effect": "Allow", "Action": ["s3:DeleteObject", "s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"}],
    )
    allowed_fn = _create_lambda_function(ctx, allowed_role_arn, _HANDLER_CODE)
    allowed_result = _invoke_lambda(ctx, allowed_fn, {"bucket": bucket, "key": allowed_key})
    assert allowed_result["status"] == "ok", (
        f"positive control: expected the delete to succeed (status=ok), got {allowed_result!r}"
    )

    code, message = _expect_error(lambda: s3.get_object(Bucket=bucket, Key=allowed_key))
    assert code == "NoSuchKey", f"positive control: expected object gone, got code={code!r}"
    assert message == "The specified key does not exist.", (
        f"positive control: expected NoSuchKey message 'The specified key does not exist.', got {message!r}"
    )


# ===== helpers =====
_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _expect_error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected success raises."""
    import botocore

    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    kwargs: dict[str, Any] = {"Bucket": bucket}
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
