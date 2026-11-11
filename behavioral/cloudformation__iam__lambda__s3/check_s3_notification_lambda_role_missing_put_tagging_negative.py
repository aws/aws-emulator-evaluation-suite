"""s3-notification-lambda-role-missing-put-tagging-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-notification-lambda-role-missing-put-tagging-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """S3 successfully invokes the Lambda on ObjectCreated, but the function's role lacks
    s3:PutObjectTagging so its internal PutObjectTagging call is rejected with AccessDenied and
    the tag is never applied; once the missing permission is added the same workflow succeeds."""
    s3 = ctx.client("s3")
    ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    # Role only allows reading/writing plain objects (needed for the invocation-marker the
    # function writes back) -- deliberately NOT s3:PutObjectTagging.
    role_name, role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject"],
                "Resource": f"{bucket_arn}/*",
            }
        ],
    )

    code = (
        "import boto3\n"
        "import urllib.parse\n"
        "from botocore.exceptions import ClientError\n"
        "s3 = boto3.client('s3')\n"
        "def handler(event, context):\n"
        "    for record in event.get('Records', []):\n"
        "        bucket = record['s3']['bucket']['name']\n"
        "        key = urllib.parse.unquote_plus(record['s3']['object']['key'])\n"
        "        status = 'OK'\n"
        "        try:\n"
        "            s3.put_object_tagging(\n"
        "                Bucket=bucket,\n"
        "                Key=key,\n"
        "                Tagging={'TagSet': [{'Key': 'ProcessedBy', 'Value': 'lambda-notification'}]},\n"
        "            )\n"
        "        except ClientError as exc:\n"
        "            err = exc.response['Error']\n"
        "            status = 'ERROR:' + err['Code'] + '|' + err.get('Message', '')\n"
        "        marker_key = 'marker/' + key.split('/')[-1] + '.status'\n"
        "        s3.put_object(Bucket=bucket, Key=marker_key, Body=status.encode())\n"
        "    return {'status': 'done'}\n"
    )
    function_name, function_arn = _create_function(ctx, role_arn, code)
    _add_s3_invoke_permission(
        ctx, function_name, bucket_arn, account_id, "s3invoke-negative"
    )

    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [
                {
                    "LambdaFunctionArn": function_arn,
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {
                            "FilterRules": [{"Name": "prefix", "Value": "trigger/"}]
                        }
                    },
                }
            ]
        },
    )

    # --- broken: role lacks s3:PutObjectTagging ---
    neg_key = "trigger/negative.txt"
    s3.put_object(Bucket=bucket, Key=neg_key, Body=b"negative-case")
    neg_marker = "marker/negative.txt.status"
    status_body = _wait_for_effect(
        lambda: _get_object_body_or_none(s3, bucket, neg_marker),
        lambda body: body is not None,
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3.0,
        description="invocation-marker for the negative-case object",
    )
    want_status = (
        f"ERROR:AccessDenied|User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{function_name} "
        f"is not authorized to perform: s3:PutObjectTagging on resource: \"{bucket_arn}/{neg_key}\" "
        f"because no identity-based policy allows the s3:PutObjectTagging action"
    )
    assert status_body == want_status, (
        f"the function's PutObjectTagging must be refused with {want_status!r}, got {status_body!r}"
    )
    # effect absent: the tag was never applied to the source object
    tags = s3.get_object_tagging(Bucket=bucket, Key=neg_key)["TagSet"]
    assert tags == [], f"expected no tags, found {tags}"

    # --- fix: grant PutObjectTagging and remove the blocking condition ---
    iam = ctx.client("iam")
    fixed_policy_name = f"{role_name}-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=fixed_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:PutObjectTagging",
                        ],
                        "Resource": f"{bucket_arn}/*",
                    }
                ],
            }
        ),
    )

    # IAM policy changes propagate asynchronously; poll the actual outcome rather than sleeping
    # a fixed duration. Use a FRESH key per attempt (not a shared key) so a stale marker from an
    # earlier, still-unpropagated invocation can never be mistaken for the outcome of a later one.
    # IAM's eventual-consistency window for inline role-policy updates can run well past a minute
    # in some accounts, so budget generously here.
    deadline = time.monotonic() + 270.0
    final_status: str | None = None
    fixed_tags: list[dict[str, str]] = []
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        pos_key = f"trigger/positive-{attempt}.txt"
        pos_marker = f"marker/positive-{attempt}.txt.status"
        s3.put_object(Bucket=bucket, Key=pos_key, Body=b"positive-case")
        body = _body_within(s3, bucket, pos_marker, timeout_s=15.0, interval_s=2.0)
        if body is None:
            continue
        final_status = body
        if body == "OK":
            fixed_tags = s3.get_object_tagging(Bucket=bucket, Key=pos_key)["TagSet"]
            break
        time.sleep(2)
    assert final_status == "OK", f"positive control never succeeded: {final_status!r}"
    assert {"Key": "ProcessedBy", "Value": "lambda-notification"} in fixed_tags, (
        f"expected ProcessedBy=lambda-notification tag after the fix, found {fixed_tags}"
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


def _body_within(s3, bucket: str, key: str, *, timeout_s: float, interval_s: float) -> str | None:
    """The object's body once it appears within timeout_s, else None (the caller's outer
    deadline bounds the retries)."""
    deadline = time.monotonic() + timeout_s
    while True:
        body = _get_object_body_or_none(s3, bucket, key)
        if body is not None or time.monotonic() >= deadline:
            return body
        time.sleep(interval_s)


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
    # CreateBucket rejects an explicit LocationConstraint for us-east-1 (its own default region).
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


def _add_s3_invoke_permission(
    ctx, function_name: str, source_arn: str, account_id: str, statement_id: str
) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=source_arn,
        SourceAccount=account_id,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=function_name, StatementId=statement_id
        )
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
