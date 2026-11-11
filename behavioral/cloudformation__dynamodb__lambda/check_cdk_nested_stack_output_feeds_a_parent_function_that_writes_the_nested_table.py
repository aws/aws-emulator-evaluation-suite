"""cdk-nested-stack-output-feeds-a-parent-function-that-writes-the-nested-table."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-nested-stack-output-feeds-a-parent-function-that-writes-the-nested-table"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "lambda"]

_APP = "cdk_nested_table_writer"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A CDK NestedStack's table name reaches the environment of a function in the parent stack.

    The parent lists the nested stack, whose ParentId and RootId are the parent, and invoking the
    function writes an item that reads back from the nested table.

    Reference: https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.NestedStack.html
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    stack = ctx.unique_name("sim2real-cdk-nest-")
    function = ctx.unique_name("sim2real-cdk-nest-")
    bucket = ctx.unique_name("sim2real-cdk-assets-")
    work = _stage_app(ctx)

    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{function}"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(
        ctx,
        work,
        ["deploy", stack, "--require-approval", "never"],
        {
            "stack_name": stack,
            "account": ctx.account,
            "region": ctx.region,
            "asset_bucket": bucket,
            "function_name": function,
        },
    )
    assert rc == 0, f"`cdk deploy` exited {rc}; output tail {out[-800:]!r}"
    parent = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert parent["StackStatus"] == "CREATE_COMPLETE", f"the parent stack is {parent!r}"
    parent_id = parent["StackId"]

    nested = [
        r
        for r in _stack_resources(cfn, parent_id)
        if r["ResourceType"] == "AWS::CloudFormation::Stack"
    ]
    assert [r["ResourceStatus"] for r in nested] == ["CREATE_COMPLETE"], (
        f"the parent's AWS::CloudFormation::Stack resources are {nested!r}"
    )
    child = cfn.describe_stacks(StackName=nested[0]["PhysicalResourceId"])["Stacks"][0]
    assert (child["StackId"], child["ParentId"], child["RootId"], child["StackStatus"]) == (
        nested[0]["PhysicalResourceId"],
        parent_id,
        parent_id,
        "CREATE_COMPLETE",
    ), f"the nested stack describes as {child!r}"

    tables = [
        r["PhysicalResourceId"]
        for r in _stack_resources(cfn, child["StackId"])
        if r["ResourceType"] == "AWS::DynamoDB::Table"
    ]
    assert len(tables) == 1, f"the nested stack holds tables {tables!r}"
    env = lam.get_function_configuration(FunctionName=function)["Environment"]["Variables"]
    assert env == {"TABLE_NAME": tables[0]}, (
        f"the parent function's environment is {env!r}, expected the nested table {tables[0]!r}"
    )

    pk = ctx.unique_name("pk-")
    marker = ctx.unique_name("marker-")
    result = _invoke(lam, function, {"pk": pk, "marker": marker})
    assert result == {"written": pk}, f"the function returned {result!r}"
    item = ddb.get_item(TableName=tables[0], Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")
    assert item == {"pk": {"S": pk}, "marker": {"S": marker}}, (
        f"GetItem on the nested table {tables[0]!r} at pk={pk!r} read {item!r}"
    )


def _invoke(lam, function: str, payload: dict, *, timeout_s: float = 90.0) -> dict:
    """Invoke synchronously, retrying a function error while the new role's grant propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        response = lam.invoke(FunctionName=function, Payload=json.dumps(payload).encode())
        body = json.loads(response["Payload"].read() or b"null")
        if "FunctionError" not in response:
            return body
        if time.monotonic() > deadline:
            raise AssertionError(f"{function} kept failing for {timeout_s}s; last error {body!r}")
        time.sleep(3.0)


def _stack_resources(cfn, stack_id: str) -> list[dict]:
    """DescribeStackResources for one stack."""
    return cfn.describe_stack_resources(StackName=stack_id)["StackResources"]


def _create_bucket(s3, bucket: str, region: str) -> None:
    """The bucket the CLI publishes the nested templates to."""
    # us-east-1 is the one region that refuses an explicit LocationConstraint.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Delete every object in the check's asset bucket, then the bucket."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _reap_log_group(
    logs, name: str, *, reads: int = 2, interval_s: float = 3.0, budget_s: float = 120.0
) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; raise if not."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


def _stage_app(ctx) -> Path:
    """Copy the CDK app into a temp dir so cdk.out stays out of the app directory."""
    source = Path(__file__).parent / "deployments" / _APP
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is missing app.py or cdk.json"
    )
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdk-app-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(source, work / _APP, ignore=shutil.ignore_patterns("cdk.out", "__pycache__"))
    return work / _APP


def _cdk(
    ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float = 600.0
) -> tuple[int, str]:
    """Run the CDK CLI against the target; returns (exit code, stdout + stderr)."""
    cmd = [
        "cdk",
        *args,
        "--app",
        f"{sys.executable} app.py",
        "--ci",
        "--no-color",
        "--no-notices",
        "--no-version-reporting",
    ]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    done = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    return done.returncode, done.stdout + done.stderr


def _delete_stack(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; a stack never created is a no-op."""
    try:
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    stack_id = stack["StackId"]
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {name} teardown ended {status!r}")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
