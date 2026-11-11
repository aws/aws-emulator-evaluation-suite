"""untag-resource-removes-tag."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["osis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource, and UntagResource removes
    exactly the named key while leaving the other tag(s) in place."""
    osis = ctx.client("osis")
    name = ctx.unique_name("sim2real-osis-")
    fixture = _create_pipeline_role_and_bucket(ctx)
    config = _pipeline_config(fixture["bucket"], fixture["role_arn"], ctx.region)
    _create_pipeline_with_retry(ctx, osis, name, 1, 1, config)
    ctx.on_cleanup(lambda: _delete_pipeline_best_effort(ctx, name))
    pipeline_arn = osis.get_pipeline(PipelineName=name)["Pipeline"]["PipelineArn"]

    osis.tag_resource(
        Arn=pipeline_arn,
        Tags=[{"Key": "sim2real-keep", "Value": "keep-me"}, {"Key": "sim2real-drop", "Value": "drop-me"}],
    )
    tags_after_tag = {t["Key"]: t["Value"] for t in osis.list_tags_for_resource(Arn=pipeline_arn)["Tags"]}
    assert tags_after_tag.get("sim2real-keep") == "keep-me"
    assert tags_after_tag.get("sim2real-drop") == "drop-me"

    osis.untag_resource(Arn=pipeline_arn, TagKeys=["sim2real-drop"])
    tags_after_untag = {t["Key"]: t["Value"] for t in osis.list_tags_for_resource(Arn=pipeline_arn)["Tags"]}
    assert tags_after_untag.get("sim2real-keep") == "keep-me"
    assert "sim2real-drop" not in tags_after_untag


# ===== helpers =====

def _pipeline_config(bucket: str, role_arn: str, region: str) -> str:
    return f"""version: "2"
osis-behav-pipeline:
  source:
    http:
      path: "/ingest"
  sink:
    - s3:
        bucket: "{bucket}"
        codec:
          ndjson:
        aws:
          sts_role_arn: "{role_arn}"
          region: "{region}"
        threshold:
          event_count: 1
          maximum_size: "1mb"
          event_collect_timeout: "60s"
"""


def _create_pipeline_role_and_bucket(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    bucket_name = ctx.unique_name("sim2real-osis-behav-")
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))

    role_name = ctx.unique_name("sim2real-osis-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "osis-pipelines.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _detach_and_delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="osis-behav-s3-sink",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:PutObjectAcl",
                            "s3:AbortMultipartUpload",
                            "s3:ListBucket",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket_name}",
                            f"arn:aws:s3:::{bucket_name}/*",
                        ],
                    }
                ],
            }
        ),
    )
    return {"role_arn": role_arn, "bucket": bucket_name, "role_name": role_name}


def _detach_and_delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_pipeline_with_retry(
    ctx, osis, name: str, min_units: int, max_units: int, config: str, timeout_s: float = 90
) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            osis.create_pipeline(
                PipelineName=name,
                MinUnits=min_units,
                MaxUnits=max_units,
                PipelineConfigurationBody=config,
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            role_not_yet_assumable = code == "ValidationException" and "Unable to assume the STS role" in message
            if (code == "ResourceNotFoundException" or role_not_yet_assumable) and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _delete_pipeline_best_effort(ctx, name: str) -> None:
    osis = ctx.client("osis")
    deadline = time.monotonic() + 720
    last = ""
    while time.monotonic() < deadline:
        try:
            last = osis.get_pipeline(PipelineName=name)["Pipeline"]["Status"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if last in ("ACTIVE", "STOPPED", "CREATE_FAILED", "UPDATE_FAILED", "START_FAILED"):
            break
        time.sleep(2)
    # DeletePipeline answers ConflictException while a transition settles: retry it, raise the rest.
    deadline = time.monotonic() + 150
    while True:
        try:
            osis.delete_pipeline(PipelineName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
