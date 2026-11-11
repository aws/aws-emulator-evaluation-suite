"""sagemaker-processing-job-s3-output-bucket-policy-blocks-write-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-processing-job-s3-output-bucket-policy-blocks-write-negative"
GROUP = "overly-permissive"
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


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bucket policy Deny on s3:PutObject for one role's ARN fails that job's output upload and
    leaves no object at its prefix, while a role not named in the Deny uploads to the same bucket."""
    s3 = ctx.client("s3")

    bucket_out = _create_bucket(ctx)
    role_ok = _create_processing_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket_out}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket_out}"},
        ],
    )
    role_neg = _create_processing_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket_out}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket_out}"},
        ],
    )
    # Break exactly one thing: an explicit Deny on s3:PutObject naming only role_neg's ARN.
    # role_ok is untouched by the Deny, so both jobs can be launched against the same bucket
    # policy at the same instant instead of requiring a sequential break-then-restore.
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyOneRolePutObject",
                "Effect": "Deny",
                "Principal": {"AWS": role_neg},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_out}/*",
            }
        ],
    }
    _put_bucket_policy_with_retry(s3, bucket_out, deny_policy)
    _wait_for_bucket_policy(s3, bucket_out, "DenyOneRolePutObject")

    entrypoint_cmd = "mkdir -p /opt/ml/processing/output && echo hello > /opt/ml/processing/output/data.txt"
    job_ok = _run_processing_job(
        ctx,
        role_arn=role_ok,
        inputs=None,
        outputs=_outputs(bucket_out, "output-ok"),
        entrypoint_cmd=entrypoint_cmd,
    )
    job_neg = _run_processing_job(
        ctx,
        role_arn=role_neg,
        inputs=None,
        outputs=_outputs(bucket_out, "output-neg"),
        entrypoint_cmd=entrypoint_cmd,
    )

    desc_ok = _wait_processing_job_terminal(ctx, job_ok)
    assert desc_ok["ProcessingJobStatus"] == "Completed", desc_ok.get("FailureReason")
    ok_body = s3.get_object(Bucket=bucket_out, Key="output-ok/data.txt")["Body"].read().decode()
    assert ok_body == "hello\n", ok_body

    desc_neg = _wait_processing_job_terminal(ctx, job_neg)
    assert desc_neg["ProcessingJobStatus"] == "Failed", desc_neg
    assert "AccessDenied" in desc_neg.get("FailureReason", ""), desc_neg.get("FailureReason")

    listing = s3.list_objects_v2(Bucket=bucket_out, Prefix="output-neg/")
    assert not listing.get("Contents"), listing.get("Contents")


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchBucket") or (
        err["Code"] == "ValidationException" and any(t in msg for t in ("not found", "could not find"))
    )


def _put_bucket_policy_with_retry(s3, bucket: str, policy: dict, *, timeout_s: float = 60.0, interval_s: float = 5.0) -> None:
    """A bucket policy whose Principal names an IAM role created moments ago can be rejected
    with MalformedPolicy/'Invalid principal in policy' until that role has propagated through
    IAM; retry the PutBucketPolicy call itself, since that is the exact call being validated
    against the new principal."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "").lower()
            if code == "MalformedPolicy" and "principal" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _wait_for_bucket_policy(s3, bucket: str, expected_sid: str, *, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        policy = s3.get_bucket_policy(Bucket=bucket)["Policy"]
        if expected_sid in policy:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"bucket policy Sid {expected_sid!r} never became visible on {bucket}")
        time.sleep(interval_s)


def _outputs(bucket_out: str, prefix: str) -> list[dict[str, Any]]:
    return [
        {
            "OutputName": "output-1",
            "S3Output": {
                "S3Uri": f"s3://{bucket_out}/{prefix}/",
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
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    # the deny policy on the "negative" bucket also blocks our own cleanup put/delete-object
    # attempts if it were broader; DeleteObject is not covered by the PutObject-only deny,
    # so cleanup still succeeds.
    try:
        s3.delete_bucket_policy(Bucket=name)
    except ClientError as exc:
        if not _gone(exc):
            raise
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
