"""s3-notification-cross-account-bucket-lambda-role-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-notification-cross-account-bucket-lambda-role-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An invoke permission scoped to another bucket's ARN makes PutBucketNotificationConfiguration
    fail with InvalidArgument and persist nothing; once the permission names this bucket, the same
    call succeeds and an object put under trigger/ invokes the function, which writes "invoked"."""
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    role_name, role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": f"{bucket_arn}/*",
            }
        ],
    )

    code = (
        "import boto3\n"
        "import urllib.parse\n"
        "s3 = boto3.client('s3')\n"
        "def handler(event, context):\n"
        "    for record in event.get('Records', []):\n"
        "        bucket = record['s3']['bucket']['name']\n"
        "        key = urllib.parse.unquote_plus(record['s3']['object']['key'])\n"
        "        marker_key = 'marker/' + key.split('/')[-1] + '.done'\n"
        "        s3.put_object(Bucket=bucket, Key=marker_key, Body=b'invoked')\n"
        "    return {'status': 'done'}\n"
    )
    function_name, function_arn = _create_function(ctx, role_arn, code)

    # Grant invoke permission scoped to a DIFFERENT bucket ARN -- this is the same shape as a
    # cross-account bucket for which the account owner never granted a matching resource policy
    # / role trust: syntactically valid, but it does not authorize *this* bucket.
    foreign_bucket_arn = f"arn:aws:s3:::{ctx.unique_name('sim2real-foreign-bkt-')}"
    lam.add_permission(
        FunctionName=function_name,
        StatementId="s3invoke-foreign",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=foreign_bucket_arn,
        SourceAccount=account_id,
    )
    def _remove_foreign_permission():
        # The fix step below removes this statement itself; teardown only covers an early failure.
        try:
            lam.remove_permission(FunctionName=function_name, StatementId="s3invoke-foreign")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_remove_foreign_permission)

    notification_config = {
        "LambdaFunctionConfigurations": [
            {
                "LambdaFunctionArn": function_arn,
                "Events": ["s3:ObjectCreated:*"],
                "Filter": {
                    "Key": {"FilterRules": [{"Name": "prefix", "Value": "trigger/"}]}
                },
            }
        ]
    }

    code_seen, message_seen = _error_code(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket, NotificationConfiguration=notification_config
        )
    )
    assert code_seen == "InvalidArgument", code_seen
    expected_message = "Unable to validate the following destination configurations"
    assert message_seen == expected_message, f"message {message_seen!r} != {expected_message!r}"

    # effect absent: no notification configuration was persisted on the bucket
    current = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert current.get("LambdaFunctionConfigurations", []) == [], (
        f"expected no persisted LambdaFunctionConfigurations after the rejected call, "
        f"found {current.get('LambdaFunctionConfigurations')!r}"
    )

    # --- fix: correct the permission's SourceArn to the real bucket ---
    lam.remove_permission(FunctionName=function_name, StatementId="s3invoke-foreign")
    lam.add_permission(
        FunctionName=function_name,
        StatementId="s3invoke-correct",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=bucket_arn,
        SourceAccount=account_id,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=function_name, StatementId="s3invoke-correct"
        )
    )

    # Lambda resource-policy changes (add_permission) can take a few seconds to become visible
    # to S3's destination-validation check; retry the identical call until it is accepted.
    deadline = time.monotonic() + 60.0
    last_code: str | None = "unset"
    while time.monotonic() < deadline:
        try:
            s3.put_bucket_notification_configuration(
                Bucket=bucket, NotificationConfiguration=notification_config
            )
            last_code = None
            break
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
        time.sleep(3)
    assert last_code is None, f"fixed configuration still rejected: {last_code}"
    fixed = s3.get_bucket_notification_configuration(Bucket=bucket)
    fixed_configs = fixed.get("LambdaFunctionConfigurations", [])
    assert len(fixed_configs) == 1, (
        f"expected exactly 1 persisted LambdaFunctionConfiguration after the fix, "
        f"found {len(fixed_configs)}: {fixed_configs!r}"
    )

    key = "trigger/hello.txt"
    marker_key = "marker/hello.txt.done"
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello-cross-account")
    body = _wait_for_effect(
        lambda: _get_object_body_or_none(s3, bucket, marker_key),
        lambda b: b is not None,
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3.0,
        description="invocation marker after the permission was corrected",
    )
    assert body == "invoked", (
        f"expected the marker object body to be 'invoked' after the lambda ran, got {body!r}"
    )


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


def _error_code(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _get_object_body_or_none(s3, bucket: str, key: str) -> str | None:
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
    except s3.exceptions.NoSuchKey:
        return None
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code in ("NoSuchKey", "404"):
            return None
        raise


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_lambda_role(ctx, inline_statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lrole-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    role_arn = role["Arn"]
    basic_exec_arn = (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    policy_name = f"{role_name}-inline"
    if inline_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": inline_statements}
            ),
        )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


def _create_function(ctx, role_arn: str, code: str, timeout: int = 30) -> tuple[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(code)
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    last_err: Exception | None = None
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"could not create function {name}: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {name} Active",
    )
    return name, resp["FunctionArn"]


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
