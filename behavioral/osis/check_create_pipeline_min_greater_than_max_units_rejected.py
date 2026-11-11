"""create-pipeline-min-greater-than-max-units-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipeline-min-greater-than-max-units-rejected"
GROUP = "overly-permissive"
SERVICES = ["osis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePipeline rejects MinUnits > MaxUnits with ValidationException and never provisions
    the pipeline, while an identical request with a valid range (run first, on the same role and
    bucket) succeeds, so the rejection is attributable to the inverted bounds."""
    osis = ctx.client("osis")
    fixture = _create_pipeline_role_and_bucket(ctx)
    config = _pipeline_config(fixture["bucket"], fixture["role_arn"], ctx.region)

    # Positive control: the same call shape, valid bounds. Waited to a terminal state here,
    # in the check's own budget, rather than left for on_cleanup: ctx.on_cleanup's teardown
    # thread gets only 60s, far under real provisioning time, so a pipeline still CREATING
    # when cleanup starts is abandoned mid-poll, never reaches delete_pipeline, and leaks.
    good_name = ctx.unique_name("sim2real-good-")
    _create_pipeline_with_retry(ctx, osis, good_name, 1, 1, config)
    ctx.on_cleanup(lambda: _delete_pipeline_best_effort(ctx, good_name))
    created = osis.get_pipeline(PipelineName=good_name)["Pipeline"]
    assert created["MinUnits"] == 1, f"positive control: expected MinUnits 1, got {created['MinUnits']!r}"
    assert created["MaxUnits"] == 1, f"positive control: expected MaxUnits 1, got {created['MaxUnits']!r}"
    status = _wait_for_pipeline_status(ctx, good_name, {"ACTIVE", "CREATE_FAILED"}, timeout_s=1200)
    assert status == "ACTIVE", f"positive control: expected pipeline to reach ACTIVE, got {status}"

    bad_name = ctx.unique_name("sim2real-bad-")
    ctx.on_cleanup(lambda: _delete_pipeline_best_effort(ctx, bad_name))
    error = _client_error(
        lambda: osis.create_pipeline(
            PipelineName=bad_name,
            MinUnits=5,
            MaxUnits=1,
            PipelineConfigurationBody=config,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for MinUnits(5) > MaxUnits(1), got {error.get('Code')!r}"
    )
    expected = "minUnits cannot be greater than maxUnits"
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    not_found = _client_error(lambda: osis.get_pipeline(PipelineName=bad_name))
    assert not_found.get("Code") == "ResourceNotFoundException", (
        f"rejected pipeline {bad_name!r} must not have been provisioned, got "
        f"{not_found.get('Code')!r}"
    )
    expected_not_found = "The pipeline could not be found"
    assert not_found.get("Message") == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found.get('Message')!r}"
    )


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so accepting
    input AWS refuses is reported as such rather than as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


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
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
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
            # IAM role propagation: the just-created PipelineRoleArn is not yet visible to
            # osis, which reports it as ResourceNotFoundException until it is.
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
