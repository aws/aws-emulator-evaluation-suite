"""cdk-sibling-nested-stacks-deliver-topic-to-queue-across-a-producer-only-update."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-sibling-nested-stacks-deliver-topic-to-queue-across-a-producer-only-update"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

_APP = "cdk_nested_topic_queue"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """A topic in one CDK NestedStack delivers to a queue subscribed in a sibling NestedStack.

    A deploy that changes only the producer updates both nested stacks in place, and delivery
    still works.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-nested-stacks.html
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    s3 = ctx.client("s3")
    stack = ctx.unique_name("sim2real-cdk-sib-")
    bucket = ctx.unique_name("sim2real-cdk-assets-")
    base = {
        "stack_name": stack,
        "account": ctx.account,
        "region": ctx.region,
        "asset_bucket": bucket,
    }
    work = _stage_app(ctx)

    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(
        ctx,
        work,
        ["deploy", stack, "--require-approval", "never", "--tags", f"sim2real-check={CHECK}"],
        {**base, "display_name": "first"},
    )
    assert rc == 0, f"the first `cdk deploy` exited {rc}; output tail {out[-800:]!r}"
    parent_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    producer, consumer = _nested(cfn, parent_id)
    topic = _physical(cfn, producer, "AWS::SNS::Topic")
    queue = _physical(cfn, consumer, "AWS::SQS::Queue")
    _assert_delivers(ctx, sns, sqs, topic, queue, "after the first deploy")

    rc, out = _cdk(
        ctx,
        work,
        ["deploy", stack, "--require-approval", "never", "--tags", f"sim2real-check={CHECK}"],
        {**base, "display_name": "second"},
    )
    assert rc == 0, f"the producer-only `cdk deploy` exited {rc}; output tail {out[-800:]!r}"
    statuses = [
        cfn.describe_stacks(StackName=s)["Stacks"][0]["StackStatus"]
        for s in (parent_id, producer, consumer)
    ]
    assert statuses == ["UPDATE_COMPLETE"] * 3, (
        f"after the producer-only update the parent, producer and consumer are {statuses!r}"
    )
    assert _nested(cfn, parent_id) == (producer, consumer), "the update replaced a nested stack"
    assert (
        _physical(cfn, producer, "AWS::SNS::Topic"),
        _physical(cfn, consumer, "AWS::SQS::Queue"),
    ) == (topic, queue), "the producer-only update replaced the topic or the queue"
    shown = sns.get_topic_attributes(TopicArn=topic)["Attributes"]["DisplayName"]
    assert shown == "second", f"the producer's topic DisplayName is {shown!r}, expected 'second'"
    _assert_delivers(ctx, sns, sqs, topic, queue, "after the producer-only update")


def _assert_delivers(
    ctx, sns, sqs, topic: str, queue: str, when: str, *, timeout_s: float = 90.0
) -> None:
    """A marker published to the topic arrives in the queue; duplicates and re-publishes allowed."""
    marker = ctx.unique_name("marker-")
    deadline = time.monotonic() + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        # Re-publishing covers a subscription or queue policy that is not yet effective.
        sns.publish(TopicArn=topic, Message=marker)
        for message in sqs.receive_message(
            QueueUrl=queue, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []):
            seen.append(message["Body"])
            sqs.delete_message(QueueUrl=queue, ReceiptHandle=message["ReceiptHandle"])
        if marker in seen:
            return
    raise AssertionError(
        f"{when}: {marker!r} never reached the queue in {timeout_s}s; saw {seen!r}"
    )


def _nested(cfn, parent_id: str) -> tuple[str, str]:
    """(producer, consumer) nested stack ids, from the parent's AWS::CloudFormation::Stack rows."""
    rows = {
        r["LogicalResourceId"].split("NestedStack")[0]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=parent_id)["StackResources"]
        if r["ResourceType"] == "AWS::CloudFormation::Stack"
    }
    assert sorted(rows) == ["Consumer", "Producer"], f"the parent's nested stacks are {rows!r}"
    return rows["Producer"], rows["Consumer"]


def _physical(cfn, stack_id: str, resource_type: str) -> str:
    """The physical id of the one resource of ``resource_type`` in the stack."""
    ids = [
        r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
        if r["ResourceType"] == resource_type
    ]
    assert len(ids) == 1, f"{stack_id} holds {resource_type} resources {ids!r}"
    return ids[0]


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
