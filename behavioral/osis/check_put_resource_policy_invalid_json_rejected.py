"""put-resource-policy-invalid-json-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-invalid-json-rejected"
GROUP = "overly-permissive"
SERVICES = ["osis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects a non-JSON Policy with ValidationException and attaches nothing,
    while a valid IAM-style policy on the same pipeline succeeds and is returned by
    GetResourcePolicy."""
    osis = ctx.client("osis")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-osis-")
    fixture = _create_pipeline_role_and_bucket(ctx)
    config = _pipeline_config(fixture["bucket"], fixture["role_arn"], ctx.region)
    _create_pipeline_with_retry(ctx, osis, name, 1, 1, config)
    ctx.on_cleanup(lambda: _delete_pipeline_best_effort(ctx, name))
    status = _wait_for_pipeline_status(ctx, name, {"ACTIVE", "CREATE_FAILED"}, timeout_s=1200)
    assert status == "ACTIVE", f"pipeline entered {status} instead of ACTIVE"
    pipeline_arn = osis.get_pipeline(PipelineName=name)["Pipeline"]["PipelineArn"]

    not_json = "{this is not valid json"
    error = _client_error(lambda: osis.put_resource_policy(ResourceArn=pipeline_arn, Policy=not_json))
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error.get('Code')!r}"
    expected = "Invalid resource policy."
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    absent_policy = json.loads(osis.get_resource_policy(ResourceArn=pipeline_arn)["Policy"])
    assert absent_policy == {}, (
        f"malformed policy must not have been attached; GetResourcePolicy has no "
        f"ResourceNotFoundException contract on osis, absence reads as an empty document, "
        f"got {absent_policy!r}"
    )

    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "osis:CreatePipelineEndpoint",
                "Resource": pipeline_arn,
            }
        ],
    }
    osis.put_resource_policy(ResourceArn=pipeline_arn, Policy=json.dumps(valid_policy))
    fetched = osis.get_resource_policy(ResourceArn=pipeline_arn)
    fetched_policy = json.loads(fetched["Policy"])
    assert fetched_policy == valid_policy, f"expected {valid_policy!r}, got {fetched_policy!r}"


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
    if region == "us-east-1":  # S3 CreateBucket rejects LocationConstraint for this region specifically
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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
    """Retries on ResourceNotFoundException, which covers the freshly-created IAM
    role not having propagated to OSIS yet, bounded by timeout_s."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            osis.create_pipeline(
                PipelineName=name,
                MinUnits=min_units,
                MaxUnits=max_units,
                PipelineConfigurationBody=config,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            # A just-created role reaches OSIS late: until it does, CreatePipeline reports it
            # as not found or as not assumable.
            not_propagated = code == "ResourceNotFoundException" or (
                code == "ValidationException"
                and "Unable to assume the STS role" in exc.response["Error"].get("Message", "")
            )
            if not_propagated and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_for_pipeline_status(
    ctx, name: str, target_statuses: set[str], timeout_s: float = 1200, interval_s: float = 20
) -> str:
    osis = ctx.client("osis")
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        last = osis.get_pipeline(PipelineName=name)["Pipeline"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"pipeline {name} did not reach {target_statuses} within {timeout_s}s (last={last})")


def _delete_pipeline_best_effort(ctx, name: str) -> None:
    osis = ctx.client("osis")
    try:
        _wait_for_pipeline_status(
            ctx, name, {"ACTIVE", "STOPPED", "CREATE_FAILED", "UPDATE_FAILED", "START_FAILED"}, timeout_s=720, interval_s=2
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
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
