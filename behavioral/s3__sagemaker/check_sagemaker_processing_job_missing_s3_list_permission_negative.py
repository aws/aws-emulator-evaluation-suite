"""sagemaker-processing-job-missing-s3-list-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-processing-job-missing-s3-list-permission-negative"
GROUP = "permission-boundary"
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateProcessingJob refuses a role with s3:GetObject but no s3:ListBucket on its S3Prefix input
    and produces no output, while an otherwise identical role with s3:ListBucket succeeds."""
    s3 = ctx.client("s3")

    # ---- positive control: an otherwise-identical role that also has s3:ListBucket on
    # the input bucket -> the S3Prefix input channel enumerates and the job completes,
    # copying the real input byte-for-byte. Launched first (not awaited yet) so it runs
    # concurrently with the negative job below instead of doubling wall-clock time.
    bucket_in_pos = _create_bucket(ctx)
    bucket_out_pos = _create_bucket(ctx)
    s3.put_object(Bucket=bucket_in_pos, Key="input/data.txt", Body=b"positive-control-input")
    role_pos = _create_processing_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket_in_pos}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket_in_pos}"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket_out_pos}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket_out_pos}"},
        ],
    )
    job_pos = _run_processing_job(
        ctx,
        role_arn=role_pos,
        inputs=_inputs(bucket_in_pos),
        outputs=_outputs(bucket_out_pos),
        entrypoint_cmd="cp /opt/ml/processing/input/data.txt /opt/ml/processing/output/data.txt",
    )

    # ---- negative: role has GetObject but NOT ListBucket -> the input channel cannot be
    # enumerated. SageMaker enumerates the S3Prefix input with the execution role at
    # CreateProcessingJob time, so the control-plane call itself is refused.
    bucket_in_neg = _create_bucket(ctx)
    bucket_out_neg = _create_bucket(ctx)
    s3.put_object(Bucket=bucket_in_neg, Key="input/data.txt", Body=b"should-never-be-read")
    role_neg = _create_processing_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket_in_neg}/*"},
            # deliberately no s3:ListBucket on bucket_in_neg
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket_out_neg}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket_out_neg}"},
        ],
    )
    try:
        _run_processing_job(
            ctx,
            role_arn=role_neg,
            inputs=_inputs(bucket_in_neg),
            outputs=_outputs(bucket_out_neg),
            entrypoint_cmd="cp /opt/ml/processing/input/data.txt /opt/ml/processing/output/data.txt",
        )
    except ClientError as err:
        error = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
    else:
        raise AssertionError(
            "CreateProcessingJob accepted a role that cannot s3:ListBucket its input prefix"
        )
    role_neg_name = role_neg.split("/")[-1]
    assert error == (
        "ValidationException",
        f'No S3 objects found under S3 URL "s3://{bucket_in_neg}/input/" given in input data '
        f"source. Please ensure that the bucket exists in the selected region ({ctx.region}), "
        f'that objects exist under that S3 prefix, and that the role "{role_neg}" has '
        f'"s3:ListBucket" permissions on bucket "{bucket_in_neg}". Error message from S3: User: '
        f"arn:aws:sts::{ctx.account}:assumed-role/{role_neg_name}/AnalyticsValidation is not "
        f'authorized to perform: s3:ListBucket on resource: "arn:aws:s3:::{bucket_in_neg}" '
        f"because no identity-based policy allows the s3:ListBucket action",
    ), error

    desc_pos = _wait_processing_job_terminal(ctx, job_pos)
    assert desc_pos["ProcessingJobStatus"] == "Completed", desc_pos.get("FailureReason")
    out_obj = s3.get_object(Bucket=bucket_out_pos, Key="output/data.txt")
    assert out_obj["Body"].read() == b"positive-control-input", (
        "positive control (role with ListBucket) did not deliver the real input bytes"
    )

    listing = s3.list_objects_v2(Bucket=bucket_out_neg, Prefix="output/")
    assert not listing.get("Contents"), listing.get("Contents")


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "RepositoryNotFoundException") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
    )


def _inputs(bucket_in: str) -> list[dict[str, Any]]:
    return [
        {
            "InputName": "input-1",
            "S3Input": {
                "S3Uri": f"s3://{bucket_in}/input/",
                "LocalPath": "/opt/ml/processing/input",
                "S3DataType": "S3Prefix",
                "S3InputMode": "File",
                "S3DataDistributionType": "FullyReplicated",
            },
        }
    ]


def _outputs(bucket_out: str) -> list[dict[str, Any]]:
    return [
        {
            "OutputName": "output-1",
            "S3Output": {
                "S3Uri": f"s3://{bucket_out}/output/",
                "LocalPath": "/opt/ml/processing/output",
                "S3UploadMode": "EndOfJob",
            },
        }
    ]


# ===== helpers =====

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
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "processing-job-missing-list-permission"}]}
    )
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
        Tags=[{"Key": "sim2real", "Value": "processing-job-missing-list-permission"}],
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
        "Tags": [{"Key": "sim2real", "Value": "processing-job-missing-list-permission"}],
    }
    if inputs:
        kwargs["ProcessingInputs"] = inputs
    _create_processing_job_with_retry(sm, kwargs)
    ctx.on_cleanup(lambda: _stop_job_quiet(sm, name))
    return name


def _stop_job_quiet(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        desc = sm.describe_processing_job(ProcessingJobName=name)
        if desc["ProcessingJobStatus"] in ("InProgress", "Stopping"):
            sm.stop_processing_job(ProcessingJobName=name)
    except ClientError as exc:
        if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_processing_job(ProcessingJobName=name)["ProcessingJobStatus"] == "InProgress"):
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
