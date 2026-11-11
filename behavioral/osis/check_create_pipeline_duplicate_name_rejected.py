"""create-pipeline-duplicate-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipeline-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["osis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePipeline with a PipelineName that already exists in the account/region is
    rejected with ResourceAlreadyExistsException, even while the original is still
    provisioning -- and the original pipeline's config is left untouched."""
    osis = ctx.client("osis")
    name = ctx.unique_name("sim2real-osis-")
    # Registered before the fixture below so it runs LAST in the LIFO teardown order: this
    # pipeline's delete blocks on OSIS reaching a terminal state, which routinely takes minutes
    # and can outrun the harness's cleanup budget. Registering it first still lets the fast
    # bucket/role teardowns get their turn even when this one is abandoned mid-poll.
    ctx.on_cleanup(lambda: _delete_pipeline_best_effort(ctx, name))
    fixture = _create_pipeline_role_and_bucket(ctx)
    config = _pipeline_config(fixture["bucket"], fixture["role_arn"], ctx.region)
    _create_pipeline_with_retry(ctx, osis, name, 1, 1, config)
    original = osis.get_pipeline(PipelineName=name)["Pipeline"]

    other_fixture = _create_pipeline_role_and_bucket(ctx)
    other_config = _pipeline_config(other_fixture["bucket"], other_fixture["role_arn"], ctx.region)
    error = _client_error(
        lambda: osis.create_pipeline(
            PipelineName=name, MinUnits=1, MaxUnits=1, PipelineConfigurationBody=other_config
        )
    )
    assert error.get("Code") == "ResourceAlreadyExistsException", (
        f"expected ResourceAlreadyExistsException, got {error.get('Code')!r}"
    )
    expected = f'Pipeline with given name "{name}" already exists'
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    unchanged = osis.get_pipeline(PipelineName=name)["Pipeline"]
    assert unchanged["PipelineConfigurationBody"] == original["PipelineConfigurationBody"], (
        f"rejected duplicate CreatePipeline must leave the original config untouched, "
        f"expected {original['PipelineConfigurationBody']!r}, got "
        f"{unchanged['PipelineConfigurationBody']!r}"
    )
    assert fixture["bucket"] in unchanged["PipelineConfigurationBody"], (
        f"expected original sink bucket {fixture['bucket']!r} to still be present in the "
        f"config, got {unchanged['PipelineConfigurationBody']!r}"
    )
    assert other_fixture["bucket"] not in unchanged["PipelineConfigurationBody"], (
        f"rejected duplicate's bucket {other_fixture['bucket']!r} must not appear in the "
        f"original's config, got {unchanged['PipelineConfigurationBody']!r}"
    )


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
    if region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for the us-east-1 default region.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "osis-behav"}]}
    )

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
        Tags=[{"Key": "sim2real", "Value": "osis-behav"}],
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
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            osis.create_pipeline(
                PipelineName=name,
                MinUnits=min_units,
                MaxUnits=max_units,
                PipelineConfigurationBody=config,
                Tags=[{"Key": "sim2real", "Value": "osis-behav"}],
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
