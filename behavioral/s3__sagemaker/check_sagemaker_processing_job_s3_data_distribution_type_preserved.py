"""sagemaker-processing-job-s3-data-distribution-type-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-processing-job-s3-data-distribution-type-preserved"
GROUP = "data-format"
SERVICES = ["s3", "sagemaker"]

_SKLEARN_ECR_ACCOUNT_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "af-south-1": "510948584623",
    "ap-east-1": "651117190479",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-northeast-3": "867004704886",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-west-3": "659782779980",
    "me-south-1": "801668240914",
    "sa-east-1": "737474898029",
}


def _processing_image_uri(ctx) -> str:
    """Region-qualified ECR URI of the AWS-owned prebuilt scikit-learn container.

    CreateProcessingJob rejects public registries (e.g. public.ecr.aws); every account
    is granted cross-account pull access to this SageMaker-maintained image in-Region.
    """
    account = _SKLEARN_ECR_ACCOUNT_BY_REGION.get(ctx.region)
    if not account:
        raise AssertionError(f"no known SageMaker scikit-learn ECR account for region {ctx.region!r}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """S3DataDistributionType on a processing input round-trips through DescribeProcessingJob
    exactly as submitted, and the job's lifecycle (stop -> terminal state) behaves normally
    for a job configured with that distribution type.
    """
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    bucket_in = _create_bucket(ctx)
    bucket_out = _create_bucket(ctx)
    s3.put_object(Bucket=bucket_in, Key="input/data.txt", Body=b"unused")

    role_arn = _create_processing_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket_in}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket_in}"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket_out}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket_out}"},
        ],
    )

    inputs = [
        {
            "InputName": "input-1",
            "S3Input": {
                "S3Uri": f"s3://{bucket_in}/input/",
                "LocalPath": "/opt/ml/processing/input",
                "S3DataType": "S3Prefix",
                "S3InputMode": "File",
                "S3DataDistributionType": "ShardedByS3Key",
            },
        }
    ]
    outputs = [
        {
            "OutputName": "output-1",
            "S3Output": {
                "S3Uri": f"s3://{bucket_out}/output/",
                "LocalPath": "/opt/ml/processing/output",
                "S3UploadMode": "EndOfJob",
            },
        }
    ]
    job_name = _run_processing_job(ctx, role_arn=role_arn, inputs=inputs, outputs=outputs, entrypoint_cmd="sleep 300")

    desc = sm.describe_processing_job(ProcessingJobName=job_name)
    s3_input = desc["ProcessingInputs"][0]["S3Input"]
    assert s3_input["S3DataDistributionType"] == "ShardedByS3Key", s3_input
    assert s3_input["S3Uri"] == f"s3://{bucket_in}/input/", (
        f"expected s3://{bucket_in}/input/, got {s3_input['S3Uri']!r}"
    )

    sm.stop_processing_job(ProcessingJobName=job_name)
    final = _poll_until(
        lambda: sm.describe_processing_job(ProcessingJobName=job_name),
        lambda d: d["ProcessingJobStatus"] in ("Stopped", "Completed", "Failed"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert final["ProcessingJobStatus"] == "Stopped", final.get("ProcessingJobStatus")
    # the distribution type must still be intact on the stopped job's description
    final_dist_type = final["ProcessingInputs"][0]["S3Input"]["S3DataDistributionType"]
    assert final_dist_type == "ShardedByS3Key", (
        f"expected ShardedByS3Key to survive to the stopped description, got {final_dist_type!r}"
    )


# ===== helpers =====

_LOGS_STATEMENT = {
    "Effect": "Allow",
    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
    "Resource": "arn:aws:logs:*:*:*",
}


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "RepositoryNotFoundException") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s (last: {last})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-smproc-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "s3-data-distribution-type-preserved"}]})
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=name)


def _create_processing_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-smproc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "s3-data-distribution-type-preserved"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-policy"
    policy_doc = {"Version": "2012-10-17", "Statement": [*statements, _LOGS_STATEMENT]}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_processing_job_with_retry(sm, kwargs: dict[str, Any], timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_processing_job(**kwargs)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err)
            if (
                code == "ValidationException"
                and ("is not authorized" in msg or "Could not assume role" in msg)
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise


def _run_processing_job(
    ctx,
    *,
    role_arn: str,
    inputs: list[dict[str, Any]] | None,
    outputs: list[dict[str, Any]],
    entrypoint_cmd: str,
    output_kms_key_id: str | None = None,
    max_runtime_s: int = 900,
) -> str:
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-smproc-job-")
    output_config: dict[str, Any] = {"Outputs": outputs}
    if output_kms_key_id:
        output_config["KmsKeyId"] = output_kms_key_id
    kwargs: dict[str, Any] = {
        "ProcessingJobName": name,
        "RoleArn": role_arn,
        "AppSpecification": {
            "ImageUri": _processing_image_uri(ctx),
            "ContainerEntrypoint": ["/bin/sh", "-c"],
            "ContainerArguments": [entrypoint_cmd],
        },
        "ProcessingResources": {
            "ClusterConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5}
        },
        "StoppingCondition": {"MaxRuntimeInSeconds": max_runtime_s},
        "ProcessingOutputConfig": output_config,
    }
    if inputs:
        kwargs["ProcessingInputs"] = inputs
    _create_processing_job_with_retry(sm, kwargs)
    ctx.on_cleanup(lambda: _stop_job_quiet(sm, name))
    return name


def _stop_job_quiet(sm, name: str) -> None:
    try:
        desc = sm.describe_processing_job(ProcessingJobName=name)
        if desc["ProcessingJobStatus"] in ("InProgress", "Stopping"):
            sm.stop_processing_job(ProcessingJobName=name)
    except ClientError as exc:
        if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_processing_job(ProcessingJobName=name)["ProcessingJobStatus"] == "InProgress"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
