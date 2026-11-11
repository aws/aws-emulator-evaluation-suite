"""s3-notification-wrong-lambda-arn-in-config-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-notification-wrong-lambda-arn-in-config-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": "sim2real-s3neg"}


def _resource_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A notification configuration naming a nonexistent Lambda ARN fails with InvalidArgument
    (exact message) and does not persist; a real function with the invoke permission on the same
    bucket is accepted and invoked by an upload."""
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    bucket_name = _create_bucket(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_fn_name = ctx.unique_name("sim2real-s3neg-ghost-")
    bogus_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:{bogus_fn_name}"

    code, message = _expect_error(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                "LambdaFunctionConfigurations": [
                    {"LambdaFunctionArn": bogus_arn, "Events": ["s3:ObjectCreated:*"]}
                ]
            },
        )
    )
    assert code == "InvalidArgument", (
        f"expected InvalidArgument for a notification config referencing a "
        f"non-existent Lambda ARN, got {code!r}"
    )
    assert message == "Unable to validate the following destination configurations", (
        f"expected message 'Unable to validate the following destination configurations', got {message!r}"
    )

    # the bad config must not have persisted
    current = s3.get_bucket_notification_configuration(Bucket=bucket_name)
    assert not current.get("LambdaFunctionConfigurations"), (
        f"rejected config persisted anyway: {current}"
    )

    # confirm the bogus function really doesn't exist (sanity on the setup)
    exists_code, exists_message = _expect_error(lambda: lam.get_function(FunctionName=bogus_fn_name))
    assert exists_code == "ResourceNotFoundException", (
        f"expected the ghost function {bogus_fn_name!r} to not exist, "
        f"got error code {exists_code!r}"
    )
    expected_missing = f"Function not found: {bogus_arn}"
    assert exists_message == expected_missing, (
        f"expected message {expected_missing!r}, got {exists_message!r}"
    )

    # Positive control: a real, permissioned function on the same bucket works.
    role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_lambda_function(ctx, role_arn, _LOG_HANDLER_CODE)
    _add_s3_invoke_permission(ctx, fn_name, bucket_name)
    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [
                {"LambdaFunctionArn": fn_arn, "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )
    key = "control/real-function.txt"
    since_ms = int(time.time() * 1000) - 5000
    s3.put_object(Bucket=bucket_name, Key=key, Body=b"real-function-payload")
    messages = _poll_for_marker(ctx, fn_name, since_ms, "S3_EVT::", timeout_s=90.0)
    records = [_parse_record(m) for m in messages]
    assert any(r and r["s3"]["object"]["key"] == key for r in records), (
        f"positive control did not invoke the real function: {records}"
    )


_LOG_HANDLER_CODE = """
import json

def handler(event, context):
    for record in event.get("Records", []):
        print("S3_EVT::" + json.dumps(record))
    return {"received": len(event.get("Records", []))}
"""


def _expect_error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3neg-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=_resource_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )
    return role_arn


def _create_lambda_function(ctx, role_arn: str, code: str, env=None, timeout=30):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-s3neg-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip(code)},
        Timeout=timeout,
        Tags=_resource_tags(),
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    fn_arn = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            fn_arn = resp["FunctionArn"]
            break
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(3)
                continue
            raise
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


def _create_bucket(ctx, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-s3neg-bkt-")
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _resource_tags_kv()})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", [])
            ]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup)
    if versioned:
        s3.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )
    return bucket_name


def _fetch_log_events(ctx, function_name: str, since_ms: int) -> list[dict[str, Any]]:
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    try:
        resp = logs.filter_log_events(logGroupName=log_group, startTime=since_ms)
    except botocore.exceptions.ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise
    return resp.get("events", [])


def _poll_for_marker(
    ctx, function_name: str, since_ms: int, marker: str, timeout_s: float = 90.0
) -> list[str]:
    def probe():
        events = _fetch_log_events(ctx, function_name, since_ms)
        return [e["message"] for e in events if marker in e["message"]]

    return _wait_for_effect(
        probe,
        lambda msgs: len(msgs) > 0,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"log message containing {marker!r} for {function_name}",
    )


def _parse_record(message: str) -> dict[str, Any] | None:
    idx = message.find("S3_EVT::")
    if idx == -1:
        return None
    try:
        return json.loads(message[idx + len("S3_EVT::") :].strip())
    except json.JSONDecodeError:
        return None


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
