"""s3-notification-missing-lambda-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-notification-missing-lambda-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "opensearch", "s3"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration naming a Lambda function without an s3.amazonaws.com grant
    is InvalidArgument "Unable to validate the following destination configurations" and persists
    nothing; after the grant the same call succeeds and the configuration lists the function."""
    bucket = _create_bucket(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _role_name, role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/*"}]
    )
    fn = _create_function(ctx, role_arn, _MARKER_HANDLER_SRC, {"MARKER_BUCKET": bucket})

    # No add_permission call yet: S3 cannot invoke this function.
    code, message = _expect_rejected(
        lambda: _put_notification(ctx, bucket, fn["arn"], ["s3:ObjectCreated:*"]),
        "PutBucketNotificationConfiguration for a Lambda destination with no s3.amazonaws.com "
        "invoke permission",
    )
    assert code == "InvalidArgument", (
        f"expected InvalidArgument when the target Lambda function has no resource-based policy "
        f"grant for s3.amazonaws.com; got {code!r}: {message!r}"
    )
    assert message == "Unable to validate the following destination configurations", (
        f"unexpected InvalidArgument message: {message!r}"
    )

    cfg = ctx.client("s3").get_bucket_notification_configuration(Bucket=bucket)
    assert not cfg.get("LambdaFunctionConfigurations"), (
        f"the rejected PutBucketNotificationConfiguration must not have persisted any Lambda "
        f"notification config; got {cfg.get('LambdaFunctionConfigurations')!r}"
    )

    # Positive control: grant the missing permission, then the identical call succeeds.
    # The resource-based policy grant can take a few seconds to propagate through S3's
    # validation path, so retry on InvalidArgument before treating it as a real failure.
    _add_s3_invoke_permission(ctx, fn["name"], bucket, account_id)
    _poll_until(
        lambda: _accepted(lambda: _put_notification(ctx, bucket, fn["arn"], ["s3:ObjectCreated:*"])),
        lambda accepted: accepted,
        timeout_s=60,
        interval_s=3,
        description="PutBucketNotificationConfiguration succeeding after permission grant (IAM/S3 propagation)",
    )

    cfg2 = ctx.client("s3").get_bucket_notification_configuration(Bucket=bucket)
    lambda_cfgs = cfg2.get("LambdaFunctionConfigurations", [])
    assert any(c["LambdaFunctionArn"] == fn["arn"] for c in lambda_cfgs), (
        f"expected {fn['arn']!r} to be present in LambdaFunctionConfigurations once the invoke "
        f"permission is granted; got {lambda_cfgs!r}"
    )

    key = "trigger.txt"
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=b"invoke-me")
    marker_key = f"processed/{key}.marker"
    _wait_for_effect(
        lambda: _object_exists(ctx, bucket, marker_key),
        lambda exists: exists,
        timeout_s=90,
        interval_s=3,
        description=f"marker object {marker_key} written by invoked Lambda",
    )


_MARKER_HANDLER_SRC = '''
import os
import urllib.parse
import boto3

s3 = boto3.client("s3")
BUCKET = os.environ["MARKER_BUCKET"]


def handler(event, context):
    for record in event.get("Records", []):
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        marker_key = "processed/" + key + ".marker"
        s3.put_object(Bucket=BUCKET, Key=marker_key, Body=b"invoked")
    return {"ok": True}
'''


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _accepted(fn) -> bool:
    """True when fn() succeeds, False while S3 still refuses it with InvalidArgument (grant
    propagation); any other error raises."""
    try:
        fn()
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "InvalidArgument":
            return False
        raise
    return True


def _expect_rejected(fn, description: str) -> tuple[str, str]:
    """The AWS error (code, message) for a call that MUST fail. Raises on unexpected success instead
    of returning a falsy sentinel: an over-permissive target accepting this call is the strongest
    signal available."""
    try:
        fn()
    except botocore.exceptions.ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be refused, but it SUCCEEDED")


def _object_exists(ctx, bucket: str, key: str) -> bool:
    try:
        ctx.client("s3").head_object(Bucket=bucket, Key=key)
        return True
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise


def _zip_code(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-osbucket-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
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


def _create_lambda_role(ctx, extra_statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-oslamrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    if extra_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline-access",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
    return role_name, role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(
    ctx, role_arn: str, source_code: str, env_vars: dict[str, str], timeout: int = 30
) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-osfn-")
    zip_bytes = _zip_code(source_code)

    def _attempt():
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            return lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env_vars},
                Tags={"sim2real": CHECK},
            )
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                return None  # role not yet propagated through IAM; retry
            raise

    resp = _poll_until(
        _attempt, lambda r: r is not None, timeout_s=60, interval_s=3, description="lambda create_function (IAM propagation)"
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2,
        description="function Active",
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _add_s3_invoke_permission(ctx, function_name: str, bucket_name: str, account_id: str) -> None:
    ctx.client("lambda").add_permission(
        FunctionName=function_name,
        StatementId="AllowS3Invoke",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=f"arn:aws:s3:::{bucket_name}",
        SourceAccount=account_id,
    )


def _put_notification(
    ctx, bucket: str, function_arn: str, events: list[str], filter_rules: list[dict[str, str]] | None = None
) -> None:
    cfg: dict[str, Any] = {"LambdaFunctionArn": function_arn, "Events": events}
    if filter_rules:
        cfg["Filter"] = {"Key": {"FilterRules": filter_rules}}
    ctx.client("s3").put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"LambdaFunctionConfigurations": [cfg]}
    )


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
