"""sagemaker-processing-job-writes-s3-output-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-processing-job-writes-s3-output-positive"
GROUP = "data-flow"
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
    CreateProcessingJob rejects public registries such as public.ecr.aws."""
    account = _SKLEARN_ECR_ACCOUNT_BY_REGION.get(ctx.region)
    if not account:
        raise AssertionError(f"no known SageMaker scikit-learn ECR account for region {ctx.region!r}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A completed processing job uploads every file written under its S3Output LocalPath:
    all three distinct files the container wrote appear at the destination prefix with their
    exact content."""
    s3 = ctx.client("s3")
    bucket_out = _create_bucket(ctx)

    role_arn = _create_processing_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket_out}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket_out}"},
        ],
    )

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
    entrypoint_cmd = (
        "mkdir -p /opt/ml/processing/output && "
        "for i in 1 2 3; do echo content-$i > /opt/ml/processing/output/file_$i.txt; done"
    )
    job_name = _run_processing_job(ctx, role_arn=role_arn, inputs=None, outputs=outputs, entrypoint_cmd=entrypoint_cmd)

    desc = _wait_processing_job_terminal(ctx, job_name)
    assert desc["ProcessingJobStatus"] == "Completed", desc.get("FailureReason")

    listing = s3.list_objects_v2(Bucket=bucket_out, Prefix="output/")
    keys = sorted(obj["Key"] for obj in listing.get("Contents", []))
    assert keys == ["output/file_1.txt", "output/file_2.txt", "output/file_3.txt"], keys
    for i in (1, 2, 3):
        body = s3.get_object(Bucket=bucket_out, Key=f"output/file_{i}.txt")["Body"].read().decode().strip()
        assert body == f"content-{i}", body


_LOGS_STATEMENT = {
    "Effect": "Allow",
    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
    "Resource": "arn:aws:logs:*:*:*",
}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-smproc-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "smproc-output"}]})
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
        Tags=[{"Key": "sim2real", "Value": "smproc-output"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-policy"
    policy_doc = {"Version": "2012-10-17", "Statement": [*statements, _LOGS_STATEMENT]}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_processing_job_with_retry(sm, kwargs: dict[str, Any], timeout_s: float = 90.0) -> None:
    from botocore.exceptions import ClientError

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
        "Tags": [{"Key": "sim2real", "Value": "smproc-output"}],
    }
    if inputs:
        kwargs["ProcessingInputs"] = inputs
    _create_processing_job_with_retry(sm, kwargs)
    ctx.on_cleanup(lambda: _stop_job_quiet(sm, name))
    return name


def _stop_job_quiet(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    if sm.describe_processing_job(ProcessingJobName=name)["ProcessingJobStatus"] != "InProgress":
        return
    try:
        sm.stop_processing_job(ProcessingJobName=name)
    except ClientError as err:
        # A job that left InProgress after the describe refuses the stop; any other refusal is a failure.
        if (
            err.response["Error"]["Code"] != "ValidationException"
            or sm.describe_processing_job(ProcessingJobName=name)["ProcessingJobStatus"] == "InProgress"
        ):
            raise


def _wait_processing_job_terminal(ctx, job_name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> dict:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    status = None
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = sm.describe_processing_job(ProcessingJobName=job_name)
        status = desc["ProcessingJobStatus"]
        if status in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"processing job {job_name} did not reach terminal state in {timeout_s}s (last: {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
