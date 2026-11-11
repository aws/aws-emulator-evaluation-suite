"""sfn-pipeline-lambda-broken-s3-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-pipeline-lambda-broken-s3-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "s3", "stepfunctions"]


def _cleanup_state_machine(ctx, arn: str) -> None:
    """Delete a state machine, then block until it is truly gone.

    StepFunctions DeleteStateMachine is asynchronous — the machine lingers in DELETING for up to
    ~a minute after the call returns. The account residual audit runs shortly after teardown, so a
    machine created by one of the last checks is still mid-deletion and gets misreported as a LEAK
    even though its delete was correctly issued. Wait out that window so teardown is deterministic.
    """
    sfn = ctx.client("stepfunctions")
    sfn.delete_state_machine(stateMachineArn=arn)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            if (
                sfn.describe_state_machine(stateMachineArn=arn).get("status")
                != "DELETING"
            ):
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        time.sleep(5)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SFN to Lambda to S3 pipeline that writes its object while the Lambda role holds
    s3:PutObject fails with the S3 write's AccessDenied and leaves no object once it is revoked,
    then succeeds again once the grant is restored."""
    bucket = _create_bucket(ctx)
    bucket_name = bucket["name"]
    bucket_arn = bucket["arn"]

    handler_code = """
import boto3, os
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    s3.put_object(Bucket=os.environ['BUCKET_NAME'], Key=event['key'], Body='data')
    return {'ok': True}
"""
    iam = ctx.client("iam")
    logs_statement = {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:*",
    }
    put_object_statement = {
        "Effect": "Allow",
        "Action": ["s3:PutObject"],
        "Resource": f"{bucket_arn}/*",
    }
    lambda_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [logs_statement, put_object_statement],
        },
    )

    def _set_lambda_can_write_s3(allowed: bool) -> None:
        statements = [logs_statement] + ([put_object_statement] if allowed else [])
        iam.put_role_policy(
            RoleName=lambda_role["name"],
            PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )

    fn = _create_function_with_retry(
        ctx, handler_code, lambda_role["arn"], {"BUCKET_NAME": bucket_name}
    )

    sfn_role_name = ctx.unique_name("sfn-broken-s3-role")
    sfn_role_resp = iam.create_role(
        RoleName=sfn_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    sfn_role_arn = sfn_role_resp["Role"]["Arn"]
    # Use the harness's policy-aware role deletion: these roles get an inline
    # put_role_policy, and a plain iam.delete_role fails with DeleteConflict while
    # any policy is still attached, leaking the role. _delete_role detaches/deletes
    # policies first.
    ctx.on_cleanup(lambda name=sfn_role_name: _delete_role(ctx, name))
    _poll_until(
        lambda: iam.get_role(RoleName=sfn_role_name),
        lambda r: r.get("Role", {}).get("Arn") == sfn_role_arn,
        timeout_s=30,
        interval_s=3,
    )

    iam.put_role_policy(
        RoleName=sfn_role_name,
        PolicyName=ctx.unique_name("sfn-broken-s3-policy"),
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["lambda:InvokeFunction"],
                        "Resource": fn["arn"],
                    }
                ],
            }
        ),
    )

    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sfn-broken-s3-sm")
    sm_resp = sfn.create_state_machine(
        name=sm_name,
        definition=json.dumps(
            {
                "StartAt": "BrokenTask",
                "States": {
                    "BrokenTask": {
                        "Type": "Task",
                        "Resource": fn["arn"],
                        "End": True,
                    }
                },
            }
        ),
        roleArn=sfn_role_arn,
        type="STANDARD",
    )
    sm_arn = sm_resp["stateMachineArn"]
    ctx.on_cleanup(lambda arn=sm_arn: _cleanup_state_machine(ctx, arn))

    def _run_execution(key: str) -> dict[str, Any]:
        exec_resp = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps({"key": key})
        )
        exec_arn = exec_resp["executionArn"]
        return _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda r: r["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=90,
            interval_s=3,
        )

    def _run_until(
        key_prefix: str, expected_status: str, *, attempts: int = 6, backoff_s: float = 15
    ) -> tuple[dict[str, Any], str]:
        """Retry a fresh execution (distinct key each attempt) until it settles into
        expected_status. SFN can cache a NEGATIVE trust resolution from before the state
        machine role's propagation completed, so a plain wait is not enough between
        attempts -- re-applying the same roleArn forces SFN to re-resolve it."""
        last: dict[str, Any] | None = None
        for i in range(attempts):
            key = f"{key_prefix}-{i}"
            last = _run_execution(key)
            if last["status"] == expected_status:
                return last, key
            sfn.update_state_machine(stateMachineArn=sm_arn, roleArn=sfn_role_arn)
            time.sleep(backoff_s)
        raise AssertionError(
            f"execution never reached {expected_status} after {attempts} attempts; "
            f"last={last!r}"
        )

    s3 = ctx.client("s3")

    def _assert_object_exists(key: str, context: str) -> None:
        try:
            s3.head_object(Bucket=bucket_name, Key=key)
        except ClientError as e:
            raise AssertionError(
                f"{context}: expected {key!r} to exist in {bucket_name!r}, got {e}"
            ) from e

    # --- Positive control: the role grants s3:PutObject, so the pipeline must succeed and the
    # object must appear at the destination via an independent read.
    _control, control_key = _run_until("control", "SUCCEEDED")
    _assert_object_exists(control_key, "positive control (s3:PutObject granted)")

    # --- Break exactly one thing: revoke s3:PutObject from the Lambda's own role.
    _set_lambda_can_write_s3(False)

    # --- The specific refusal, and effect-absent at the destination.
    broken, broken_key = _run_until("broken", "FAILED")
    cause_str = (broken.get("cause", "") + broken.get("error", "")).lower()
    assert "accessdenied" in cause_str, (
        f"Expected the S3 write's own AccessDenied in the task failure cause, got: {broken}"
    )
    err, err_message = _error_code(lambda: s3.head_object(Bucket=bucket_name, Key=broken_key))
    assert (err, err_message) == ("404", "Not Found"), (
        f"Object should not exist when the Lambda cannot write to S3, got {err!r}: {err_message!r}"
    )

    # --- Restore: the identical call now succeeds again.
    _set_lambda_can_write_s3(True)
    _restored, restored_key = _run_until("restored", "SUCCEEDED")
    _assert_object_exists(restored_key, "restore (s3:PutObject re-granted)")


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


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    # No propagation sleep here: _create_function_with_retry already retries past the
    # lambda.amazonaws.com trust-propagation window with a bounded deadline, and the SFN
    # role (created separately in `run`) is verified via `_poll_until` on `get_role`.
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
    """S3 buckets must be emptied before deletion — a raw delete_bucket on a non-empty bucket fails
    with BucketNotEmpty and (since teardown swallows errors) leaks the bucket. Purge objects AND all
    versions/delete-markers (versioning may be on), then delete."""
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
    # Dedent the inline source and alias `handler` to `lambda_handler`, the fixed entrypoint;
    # without that symbol the function fails with Runtime.HandlerNotFound.
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
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion and sweep_account doesn't scan log groups, so it would leak. Delete it
            # too (best-effort — on_cleanup swallows if it was never created).
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


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
