"""cdk-default-deploy-all-two-stacks-share-an-export."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-default-deploy-all-two-stacks-share-an-export"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "s3", "ssm"]

_APP = "cdk_default_two_stacks"
_CLI_TIMEOUT_S = 900.0
_ANALYTICS = re.compile(r"v2:deflate64:[A-Za-z0-9+/]+={0,2}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A default `cdk deploy --all` creates two stacks that share an export.

    After `cdk bootstrap`, both complete with an `AWS::CDK::Metadata` resource; the consumer imports
    the producer's table name into an SSM parameter, and the table serves a write.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/usage-data.html
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    ssm = ctx.client("ssm")
    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    producer = ctx.unique_name("sim2real-cdkmeta-producer-")
    consumer = ctx.unique_name("sim2real-cdkmeta-consumer-")
    param = "/" + ctx.unique_name("sim2real-cdkmeta-consumer-")
    context = {
        "producer_name": producer,
        "consumer_name": consumer,
        "account": ctx.account,
        "region": ctx.region,
        "qualifier": qualifier,
        "param_name": param,
    }
    work = _stage_app(ctx)
    _bootstrap(ctx, qualifier, toolkit_stack)
    # LIFO: the importing consumer is deleted before the exporting producer.
    ctx.on_cleanup(lambda: _delete_stack(cfn, producer))
    ctx.on_cleanup(lambda: _delete_stack(cfn, consumer))

    rc, out = _cdk(
        ctx,
        work,
        ["deploy", "--all", "--require-approval", "never", "--toolkit-stack-name", toolkit_stack],
        context,
    )
    assert rc == 0, f"`cdk deploy --all` exited {rc}; output tail {out[-800:]!r}"
    made = _deployed(cfn, producer)
    used = _deployed(cfn, consumer)
    _assert_metadata(cfn, made["StackId"])
    _assert_metadata(cfn, used["StackId"])

    tables = [
        r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=made["StackId"])["StackResources"]
        if r["ResourceType"] == "AWS::DynamoDB::Table"
    ]
    assert len(tables) == 1, f"the producer holds tables {tables!r}"
    table = tables[0]
    exports = [
        (e["Name"], e["Value"])
        for page in cfn.get_paginator("list_exports").paginate()
        for e in page["Exports"]
        if e["ExportingStackId"] == made["StackId"]
    ]
    assert [value for _, value in exports] == [table], (
        f"the producer exports {exports!r}; its table is {table!r}"
    )
    export_name = exports[0][0]
    assert re.fullmatch(rf"{re.escape(producer)}:ExportsOutputRefTable[A-Za-z0-9]+", export_name), (
        f"the producer's export is named {export_name!r}"
    )
    imports = cfn.list_imports(ExportName=export_name)["Imports"]
    assert imports == [consumer], f"ListImports on {export_name} gives {imports!r}"
    stored = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert stored == table, f"the consumer's parameter holds {stored!r}, the table is {table!r}"

    status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
    assert status == "ACTIVE", f"DescribeTable on {table} gives {status!r}"
    key, marker = ctx.unique_name("pk-"), ctx.unique_name("marker-")
    ddb.put_item(TableName=table, Item={"pk": {"S": key}, "marker": {"S": marker}})
    item = ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
    assert item == {"pk": {"S": key}, "marker": {"S": marker}}, f"GetItem returns {item!r}"


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


def _cli_env(ctx) -> dict[str, str]:
    """The target's subprocess env with CDK CLI telemetry off.

    CLI telemetry is separate from version reporting: turning it off keeps the CLI from
    contacting any host but the target, while the app still synthesizes `AWS::CDK::Metadata`.
    """
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    return env


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str]) -> tuple[int, str]:
    """Run the CDK CLI with its default version reporting; returns (exit code, stdout + stderr)."""
    cmd = ["cdk", *args, "--app", f"{sys.executable} app.py", "--ci", "--no-color", "--no-notices"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    done = subprocess.run(
        cmd, cwd=work, env=_cli_env(ctx), capture_output=True, text=True, timeout=_CLI_TIMEOUT_S
    )
    return done.returncode, done.stdout + done.stderr


def _deployed(cfn, name: str) -> dict:
    """The stack's description, which must be CREATE_COMPLETE."""
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {name} is {stack['StackStatus']!r} after `cdk deploy`: "
        f"{stack.get('StackStatusReason')!r}"
    )
    return stack


def _assert_metadata(cfn, stack_id: str) -> None:
    """The stack holds a created `CDKMetadata` resource whose template carries `Analytics`."""
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    found = [
        (r["ResourceType"], r["ResourceStatus"])
        for r in resources
        if r["LogicalResourceId"] == "CDKMetadata"
    ]
    assert found == [("AWS::CDK::Metadata", "CREATE_COMPLETE")], (
        f"DescribeStackResources on {stack_id} lists CDKMetadata as {found!r}"
    )
    body = cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"]
    template = json.loads(body) if isinstance(body, str) else body
    metadata = template["Resources"].get("CDKMetadata", {})
    shape = (metadata.get("Type"), sorted(metadata.get("Properties", {})))
    assert shape == ("AWS::CDK::Metadata", ["Analytics"]), (
        f"GetTemplate on {stack_id} carries CDKMetadata as {metadata!r}"
    )
    analytics = metadata["Properties"]["Analytics"]
    assert _ANALYTICS.fullmatch(analytics), f"CDKMetadata Analytics is {analytics!r}"


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


def _bootstrap(ctx, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for a per-run qualifier; what it creates is torn down by this run."""
    s3 = ctx.client("s3")
    bucket = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    # The staging bucket has DeletionPolicy: Retain, so it is emptied and deleted after the stack;
    # the container-assets ECR repo has no DeletionPolicy and goes with the stack.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    ctx.on_cleanup(lambda: _delete_stack(ctx.client("cloudformation"), toolkit_stack))
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdk-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    cmd = [
        "cdk",
        "bootstrap",
        f"aws://{ctx.account}/{ctx.region}",
        "--qualifier",
        qualifier,
        "--toolkit-stack-name",
        toolkit_stack,
        "--bootstrap-kms-key-id",
        "AWS_MANAGED_KEY",
        "--ci",
        "--no-color",
        "--no-notices",
    ]
    done = subprocess.run(
        cmd, cwd=scratch, env=_cli_env(ctx), capture_output=True, text=True, timeout=_CLI_TIMEOUT_S
    )
    assert done.returncode == 0, (
        f"`cdk bootstrap` exited {done.returncode}; output tail "
        f"{(done.stdout + done.stderr)[-800:]!r}"
    )


def _delete_bucket(s3, bucket: str) -> None:
    """Purge every object version and delete marker, then delete the bucket."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get(
                    "Errors", []
                )
                assert not failed, f"DeleteObjects in {bucket} left {failed!r}"
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
