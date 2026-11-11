"""op-contract-putBucketNotificationConfiguration."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-putBucketNotificationConfiguration"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a Lambda destination it cannot validate, as real S3 returns it.
_UNVALIDATED_DESTINATION = ("InvalidArgument", "Unable to validate the following destination configurations")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration persists EventBridge wiring and a validated, permissioned
    Lambda destination; rejects a Lambda destination it cannot validate."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    # success path: EventBridge destination requires no external permission wiring
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
    )
    resp = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in resp, f"expected EventBridgeConfiguration, got {resp}"

    # clear it back out and confirm the configuration reverts
    s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration={})
    resp2 = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" not in resp2, f"expected EventBridge cleared, got {resp2}"

    # positive control: a real, permissioned Lambda destination is validated and persists —
    # without this, a target that rejects every Lambda destination would still pass the
    # unvalidatable-destination check below
    role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_lambda_function(ctx, role_arn)
    _add_s3_invoke_permission(ctx, fn_name, bucket)
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [
                {"LambdaFunctionArn": fn_arn, "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )
    resp3 = s3.get_bucket_notification_configuration(Bucket=bucket)
    configured_arns = [c["LambdaFunctionArn"] for c in resp3.get("LambdaFunctionConfigurations", [])]
    assert fn_arn in configured_arns, f"expected {fn_arn} configured, got {resp3}"
    s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration={})

    # distinct error boundary: a Lambda destination that cannot be validated/invoked is rejected
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_fn_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:{ctx.unique_name('sim2real-nofn-')}"
    code = _error(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket,
            NotificationConfiguration={
                "LambdaFunctionConfigurations": [
                    {"LambdaFunctionArn": fake_fn_arn, "Events": ["s3:ObjectCreated:*"]}
                ]
            },
        )
    )
    assert code == _UNVALIDATED_DESTINATION, f"expected InvalidArgument for unvalidatable destination, got {code}"

    # the rejected call must not have partially applied — confirm via an independent read
    resp4 = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert not resp4.get("LambdaFunctionConfigurations"), (
        f"a rejected PutBucketNotificationConfiguration must not partially apply, got {resp4}"
    )


_BUCKET_PREFIX = "sim2real-behav-"

_LAMBDA_CODE = """
def handler(event, context):
    return {"received": len(event.get("Records", []))}
"""


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name(_BUCKET_PREFIX)
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _error(fn):
    """Return the ClientError (Code, Message) of fn(); raise AssertionError when fn() succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    return role_arn


def _create_lambda_function(ctx, role_arn: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip(_LAMBDA_CODE)},
        Timeout=30,
    )
    deadline = time.monotonic() + 60
    fn_arn = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            fn_arn = resp["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(3)
            continue
    if fn_arn is None:
        raise AssertionError(f"could not create lambda function: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda function {fn_name} Active",
    )
    return fn_name, fn_arn


def _add_s3_invoke_permission(ctx, function_name: str, bucket_name: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowS3Invoke",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=f"arn:aws:s3:::{bucket_name}",
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
