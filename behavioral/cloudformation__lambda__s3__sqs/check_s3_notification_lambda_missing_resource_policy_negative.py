"""s3-notification-lambda-missing-resource-policy-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError
from botocore.exceptions import ClientError as BotoClientError

from behavioral_harness import tags

CHECK = "s3-notification-lambda-missing-resource-policy-negative"

GROUP = "overly-permissive"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]

_UNVALIDATED_DESTINATION = "Unable to validate the following destination configurations"


@tags("axis:rejection", "cap:c1", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A new Lambda notification destination with no s3.amazonaws.com invoke grant fails with
    InvalidArgument "Unable to validate the following destination configurations"; a granted
    destination is accepted and delivers, and so does the rejected one once granted."""
    bucket = _create_bucket(ctx)
    result_queue = _create_queue(ctx)

    handler_code = """
import boto3, os
def lambda_handler(event, context):
    sqs = boto3.client('sqs')
    for record in event.get('Records', []):
        key = record['s3']['object']['key']
        sqs.send_message(
            QueueUrl=os.environ['RESULT_QUEUE_URL'],
            MessageBody=key
        )
    return {'ok': True}
"""
    permissions = [{"Action": ["sqs:SendMessage"], "Resource": result_queue["arn"]}]
    env = {"RESULT_QUEUE_URL": result_queue["url"]}
    fn_ok = _create_lambda(ctx, handler_code=handler_code, permissions=permissions, env=env)
    fn_blocked = _create_lambda(ctx, handler_code=handler_code, permissions=permissions, env=env)

    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    def grant(fn: dict[str, str]) -> None:
        lam.add_permission(
            FunctionName=fn["name"],
            StatementId="AllowS3Invoke",
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
            SourceArn=bucket["arn"],
            SourceAccount=account_id,
        )

    def config_for(fn: dict[str, str]) -> dict:
        return {
            "LambdaFunctionConfigurations": [
                {"LambdaFunctionArn": fn["arn"], "Events": ["s3:ObjectCreated:*"]}
            ]
        }

    def deliver_and_assert(key: str) -> None:
        """put_object, then the independent read at the consumer: poll the result queue for the
        notification and consume it so it cannot be mistaken for a later delivery."""
        s3.put_object(Bucket=bucket["name"], Key=key, Body=b"payload")
        msg = _poll_until(
            lambda: sqs.receive_message(
                QueueUrl=result_queue["url"], MaxNumberOfMessages=5, WaitTimeSeconds=10
            ),
            lambda r: r.get("Messages"),
            timeout_s=90,
            interval_s=5,
            description=f"notification for {key} delivered to result queue",
        )
        bodies = [m["Body"] for m in msg["Messages"]]
        assert key in bodies, f"expected {key} among delivered bodies, got {bodies}"
        sqs.delete_message(
            QueueUrl=result_queue["url"],
            ReceiptHandle=msg["Messages"][bodies.index(key)]["ReceiptHandle"],
        )

    # --- positive control: a brand-new destination WITH the invoke grant is accepted and delivers,
    # proving the bucket, queue and account are otherwise healthy for this. ---
    grant(fn_ok)
    _put_once_granted(s3, bucket["name"], config_for(fn_ok))
    deliver_and_assert("control/ok.txt")

    # --- the negative: a brand-new destination with NO invoke grant is rejected outright, so it is
    # never applied — the absence is structural (nothing was ever configured to deliver), not timed. ---
    blocked_config = config_for(fn_blocked)
    try:
        s3.put_bucket_notification_configuration(
            Bucket=bucket["name"], NotificationConfiguration=blocked_config
        )
    except BotoClientError as e:
        err_code = e.response["Error"]["Code"]
        err_msg = e.response["Error"].get("Message", "")
    else:
        raise AssertionError(
            "put_bucket_notification_configuration accepted a Lambda destination with no "
            "resource-based policy granting s3.amazonaws.com invoke access"
        )
    assert err_code == "InvalidArgument", f"expected InvalidArgument, got {err_code} - {err_msg}"
    assert err_msg == _UNVALIDATED_DESTINATION, (
        f"InvalidArgument message {err_msg!r} != {_UNVALIDATED_DESTINATION!r}"
    )

    # --- restore: grant the same missing permission, then the identical call — still a first-ever
    # add for this destination, since the rejected attempt was never applied — now succeeds and
    # delivers, proving the earlier rejection was specifically about the missing grant. ---
    grant(fn_blocked)
    _put_once_granted(s3, bucket["name"], blocked_config)
    deliver_and_assert("control/restored.txt")


def _put_once_granted(s3, bucket_name: str, config: dict, timeout_s: float = 30.0) -> None:
    """PutBucketNotificationConfiguration right after AddPermission: retry the destination
    validation refusal only, through the resource-policy propagation window."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.put_bucket_notification_configuration(
                Bucket=bucket_name, NotificationConfiguration=config
            )
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidArgument" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _delete_log_group_if_present(ctx, group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=group)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
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


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Delete every object version and delete marker (versioning may be on), then the bucket:
    DeleteBucket on a non-empty bucket fails with BucketNotEmpty."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError:
        try:
            p2 = s3.get_paginator("list_objects_v2")
            for page in p2.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    s3.delete_bucket(Bucket=bucket)


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, since the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function creates /aws/lambda/<name> on its first invoke and the group outlives the
            # function, so delete it too; a group that was never created is already clean.
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
