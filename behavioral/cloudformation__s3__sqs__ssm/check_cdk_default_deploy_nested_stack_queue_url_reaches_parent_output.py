"""cdk-default-deploy-nested-stack-queue-url-reaches-parent-output."""

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

CHECK = "cdk-default-deploy-nested-stack-queue-url-reaches-parent-output"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "sqs", "ssm"]

_APP = "cdk_default_nested_queue"
_CLI_TIMEOUT_S = 900.0
_ARRIVAL_BUDGET_S = 60.0
_ANALYTICS = re.compile(r"v2:deflate64:[A-Za-z0-9+/]+={0,2}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A default `cdk deploy` of a parent with a `NestedStack` passes the nested queue's URL up.

    After `cdk bootstrap`, both stacks complete with an `AWS::CDK::Metadata` resource, and the
    parent's output and SSM parameter hold the queue URL that SQS reports.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/usage-data.html
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkmeta-nested-")
    queue = ctx.unique_name("sim2real-cdkmeta-nested-")
    param = "/" + ctx.unique_name("sim2real-cdkmeta-nested-")
    context = {
        "stack_name": stack,
        "account": ctx.account,
        "region": ctx.region,
        "qualifier": qualifier,
        "queue_name": queue,
        "param_name": param,
    }
    work = _stage_app(ctx)
    _bootstrap(ctx, qualifier, toolkit_stack)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(
        ctx,
        work,
        [
            "deploy",
            stack,
            "--require-approval",
            "never",
            "--toolkit-stack-name",
            toolkit_stack,
            "--tags",
            f"sim2real={CHECK}",
        ],
        context,
    )
    assert rc == 0, f"`cdk deploy` exited {rc}; output tail {out[-800:]!r}"
    parent = _deployed(cfn, stack)
    _assert_metadata(cfn, parent["StackId"])

    nested = [
        r
        for r in cfn.describe_stack_resources(StackName=parent["StackId"])["StackResources"]
        if r["ResourceType"] == "AWS::CloudFormation::Stack"
    ]
    assert [r["ResourceStatus"] for r in nested] == ["CREATE_COMPLETE"], (
        f"the parent's nested stack resources are {nested!r}"
    )
    nested_id = nested[0]["PhysicalResourceId"]
    child = cfn.describe_stacks(StackName=nested_id)["Stacks"][0]
    assert (child["StackStatus"], child["ParentId"], child["RootId"]) == (
        "CREATE_COMPLETE",
        parent["StackId"],
        parent["StackId"],
    ), f"the nested stack is {child['StackStatus']!r} with parent {child.get('ParentId')!r}"
    _assert_metadata(cfn, nested_id)

    url = sqs.get_queue_url(QueueName=queue)["QueueUrl"]
    assert _outputs(parent) == {"QueueUrl": url}, (
        f"the parent outputs {_outputs(parent)!r}; SQS reports the nested queue at {url!r}"
    )
    stored = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert stored == url, f"the parent's parameter holds {stored!r}, SQS reports {url!r}"
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]
    assert arn == {"QueueArn": f"arn:aws:sqs:{ctx.region}:{ctx.account}:{queue}"}, (
        f"GetQueueAttributes on the nested queue gives {arn!r}"
    )

    marker = ctx.unique_name("nested-")
    sent = sqs.send_message(QueueUrl=url, MessageBody=marker)["MessageId"]
    received = _poll_receive(sqs, url, marker)
    assert received["MessageId"] == sent, f"the nested queue returned {received!r}"
    sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])


def _poll_receive(sqs, url: str, marker: str) -> dict:
    """The first message carrying ``marker``; duplicates are ignored."""
    deadline = time.monotonic() + _ARRIVAL_BUDGET_S
    while True:
        got = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", []
        )
        mine = [m for m in got if m["Body"] == marker]
        if mine:
            return mine[0]
        assert time.monotonic() < deadline, f"{marker} never arrived on {url}"


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


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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
        "--tags",
        f"sim2real={CHECK}",
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
