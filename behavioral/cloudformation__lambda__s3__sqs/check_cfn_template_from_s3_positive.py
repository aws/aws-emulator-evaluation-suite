"""cfn-template-from-s3-positive."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-template-from-s3-positive"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CFN stack created from template URL stored in S3."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    # Simple CFN template to upload
    simple_template = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Simple SQS queue for S3-template-URL test
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'sim2real-xsvc-s3tmpl-${AWS::StackName}'
Outputs:
  QueueUrl:
    Value: !Ref Queue
"""
    template_key = "cfn-templates/simple-queue.yaml"
    s3.put_object(
        Bucket=bucket["name"],
        Key=template_key,
        Body=simple_template.encode(),
        ContentType="text/yaml",
    )

    template_url = (
        f"https://{bucket['name']}.s3.{ctx.region}.amazonaws.com/{template_key}"
    )

    stack_name = ctx.unique_name("s3tmpl-stack")
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateURL=template_url,
        Capabilities=[],
    )
    ctx.on_cleanup(
        lambda: ctx.client("cloudformation").delete_stack(StackName=stack_name)
    )

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    desc = cfn.describe_stacks(StackName=stack_name)
    stack = desc["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {stack['StackStatus']}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    queue_url = outputs.get("QueueUrl")
    assert queue_url, f"QueueUrl output missing or empty: {outputs}"

    # The stack output is CFN's own echo of Ref Queue; an independent read at the
    # destination (SQS, not CFN) is what proves the queue fetched from the S3
    # template body actually exists rather than the resource having failed silently
    # into a stale/absent output.
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    queue_arn = attrs["Attributes"]["QueueArn"]
    assert queue_arn.startswith("arn:aws:sqs:"), f"unexpected QueueArn: {queue_arn}"
    assert stack_name in queue_arn, (
        f"expected stack name {stack_name!r} in queue name from ARN, got {queue_arn}"
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
