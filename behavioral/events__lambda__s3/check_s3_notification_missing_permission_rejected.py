"""s3-notification-missing-permission-rejected."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-notification-missing-permission-rejected"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration with a Lambda target that lacks an invoke grant fails
    with InvalidArgument and its exact message, leaving the stored configuration unchanged; the
    same call succeeds once the grant exists."""
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket = _create_bucket(ctx)

    code = "def lambda_handler(event, context):\n    return {'ok': True}\n"
    fn = _create_lambda(ctx, code, permissions=[])

    stmt_id = "sim2real-s3-invoke"

    def grant():
        lam.add_permission(
            FunctionName=fn["name"],
            StatementId=stmt_id,
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
            SourceArn=bucket["arn"],
            SourceAccount=account_id,
        )

    def revoke():
        lam.remove_permission(FunctionName=fn["name"], StatementId=stmt_id)

    def put(events):
        s3.put_bucket_notification_configuration(
            Bucket=bucket["name"],
            NotificationConfiguration={
                "LambdaFunctionConfigurations": [
                    {"LambdaFunctionArn": fn["arn"], "Events": events}
                ]
            },
        )

    def put_once_granted(events):
        """The invoke grant was added moments ago; S3 can still draw InvalidArgument while the
        Lambda resource policy propagates, so retry that one refusal, bounded."""
        deadline = time.monotonic() + 60.0
        while True:
            try:
                put(events)
                return
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidArgument" or time.monotonic() >= deadline:
                    raise
            time.sleep(5)

    def stored_events() -> list[list[str]]:
        cfg = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
        return [c["Events"] for c in cfg.get("LambdaFunctionConfigurations", [])]

    # ---- positive control: with the grant in place, the call succeeds and persists ----
    grant()
    put_once_granted(["s3:ObjectCreated:*"])
    assert stored_events() == [["s3:ObjectCreated:*"]], (
        "positive control: PutBucketNotificationConfiguration did not persist with the "
        "invoke grant present"
    )

    # ---- break exactly one thing: revoke the grant ----
    revoke()

    # A different event set than the positive control's, so a no-op/idempotent short-circuit on
    # an unchanged body can't fake the rejection.
    err, err_message = _error(lambda: put(["s3:ObjectRemoved:*"]))
    assert err == "InvalidArgument", (
        f"expected S3 to reject notification config lacking Lambda invoke permission with "
        f"InvalidArgument, got {err!r}"
    )
    expected_message = "Unable to validate the following destination configurations"
    assert err_message == expected_message, (
        f"expected S3's message {expected_message!r}, got {err_message!r}"
    )

    # ---- effect absent, via an independent read: the rejected call left the prior config alone ----
    after_reject = stored_events()
    assert after_reject == [["s3:ObjectCreated:*"]], (
        f"the rejected PutBucketNotificationConfiguration call changed the bucket's stored "
        f"config; expected the pre-existing ObjectCreated config untouched, got {after_reject!r}"
    )

    # ---- restore: re-grant, and the IDENTICAL call that was just rejected now succeeds ----
    grant()
    put_once_granted(["s3:ObjectRemoved:*"])
    after_restore = stored_events()
    assert after_restore == [["s3:ObjectRemoved:*"]], (
        f"expected the identical call to succeed once the invoke grant was restored, "
        f"got {after_restore!r}"
    )


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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) if it raised a ClientError. An unexpected
    SUCCESS raises rather than returning a falsy sentinel — a target that accepts input real AWS
    refuses is the strongest signal available here."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED — S3 accepted a notification "
        "config pointing at a Lambda function it has no invoke permission for"
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
    # IAM role trust/permission propagation is bounded downstream, in
    # _create_function_with_retry's retry-on-"cannot be assumed" loop, rather than by a blind
    # sleep here.
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
    """S3 buckets must be emptied before deletion: DeleteBucket on a non-empty bucket fails
    with BucketNotEmpty. Purge objects AND all versions/delete-markers (versioning may be on),
    then delete."""
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
    deadline = time.monotonic() + 45
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function creates /aws/lambda/<name> on first invoke and the group outlives the
            # function, so delete it too; a function never invoked has no log group to delete.
            ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx, f"/aws/lambda/{name}"))
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


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":  # us-east-1 is S3's default region; it rejects a LocationConstraint
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _delete_log_group_if_exists(ctx, log_group_name: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
