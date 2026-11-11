"""s3-trigger-lambda-starts-sfn-pipeline."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-trigger-lambda-starts-sfn-pipeline"

GROUP = "event-propagation"

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


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Full pipeline: S3 PutObject → Lambda (via notification) → Lambda starts SFN execution."""
    iam = ctx.client("iam")
    sfn_role_name = ctx.unique_name("sfn-full-pipe-role")
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

    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sfn-full-pipe-sm")
    sm_resp = sfn.create_state_machine(
        name=sm_name,
        definition=json.dumps(
            {
                "StartAt": "Pass",
                "States": {"Pass": {"Type": "Pass", "End": True}},
            }
        ),
        roleArn=sfn_role_arn,
        type="STANDARD",
    )
    sm_arn = sm_resp["stateMachineArn"]
    ctx.on_cleanup(lambda arn=sm_arn: _cleanup_state_machine(ctx, arn))

    bucket = _create_bucket(ctx)
    bucket_name = bucket["name"]
    bucket_arn = bucket["arn"]

    handler_code = """
import boto3, json, os
def lambda_handler(event, context):
    sfn_client = boto3.client('stepfunctions')
    s3 = boto3.client('s3')
    sm_arn = os.environ['STATE_MACHINE_ARN']
    bucket = os.environ['BUCKET_NAME']
    s3_event = event.get('Records', [{}])[0].get('s3', {})
    exec_input = json.dumps({'s3Event': s3_event})
    exec_resp = sfn_client.start_execution(stateMachineArn=sm_arn, input=exec_input)
    exec_arn = exec_resp['executionArn']
    s3.put_object(Bucket=bucket, Key='results/exec-arn.txt', Body=exec_arn)
    return {'executionArn': exec_arn}
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {"Action": ["states:StartExecution"], "Resource": sm_arn},
            {"Action": ["s3:GetObject"], "Resource": f"{bucket_arn}/*"},
            {"Action": ["s3:PutObject"], "Resource": f"{bucket_arn}/*"},
            {
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
        ],
        env={"STATE_MACHINE_ARN": sm_arn, "BUCKET_NAME": bucket_name},
    )

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="s3-invoke-pipeline",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=bucket_arn,
    )

    s3 = ctx.client("s3")
    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [
                {
                    "LambdaFunctionArn": fn["arn"],
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

    s3.put_object(Bucket=bucket_name, Key="trigger/start.txt", Body="kick-off")

    def get_exec_arn():
        try:
            obj = s3.get_object(Bucket=bucket_name, Key="results/exec-arn.txt")
            return obj["Body"].read().decode().strip()
        except Exception:
            return None

    exec_arn = _poll_until(
        get_exec_arn, lambda v: v is not None, timeout_s=90, interval_s=5
    )
    assert exec_arn, "results/exec-arn.txt not found — Lambda not triggered"

    exec_desc = sfn.describe_execution(executionArn=exec_arn)
    assert exec_desc["status"] in ("RUNNING", "SUCCEEDED"), (
        f"Unexpected SFN status: {exec_desc['status']}"
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
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler. (Folds in the dedent+alias
    # that ~8 per-suite harness overrides used to do, so no suite needs its own create_lambda shim.)
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
