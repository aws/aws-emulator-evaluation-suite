"""sagemaker-processing-job-missing-s3-putobject-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-processing-job-missing-s3-putobject-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]

_PROC_SCRIPT = """
import os

os.makedirs("/opt/ml/processing/output/results", exist_ok=True)
with open("/opt/ml/processing/output/results/summary.txt", "w") as f:
    f.write("processed\\n")
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Processing job whose execution role lacks s3:PutObject on the output bucket
    completes its container but fails when the SageMaker-managed step uploads local
    output to S3; a role with the permission (in the same file) succeeds and delivers."""
    image_uri = _resolve_sklearn_image(ctx)
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="code/process.py", Body=_PROC_SCRIPT.encode())

    good_role_arn = _create_sagemaker_role(ctx, bucket, allow_put=True)
    bad_role_arn = _create_sagemaker_role(ctx, bucket, allow_put=False)

    good_job = _run_processing_job(ctx, bucket, image_uri, good_role_arn, "good")
    bad_job = _run_processing_job(ctx, bucket, image_uri, bad_role_arn, "bad")

    good_desc = _wait_for_processing_job(ctx, good_job)
    assert good_desc["ProcessingJobStatus"] == "Completed", good_desc.get("FailureReason")
    s3.get_object(Bucket=bucket, Key="good/output/summary.txt")  # positive control: delivered

    bad_desc = _wait_for_processing_job(ctx, bad_job)
    assert bad_desc["ProcessingJobStatus"] == "Failed", f"expected Failed, got {bad_desc['ProcessingJobStatus']}"
    assert "AccessDenied" in bad_desc.get("FailureReason", ""), bad_desc.get("FailureReason")
    code = _error_code(lambda: s3.head_object(Bucket=bucket, Key="bad/output/summary.txt"))
    assert code == "404", f"denied role's output must never land in S3, got head_object code {code}"


# ===== helpers =====


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "RepositoryNotFoundException") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
    )


def _error_code(fn):
    """Call fn(); return its error code. An unexpected SUCCESS raises rather than returning a
    falsy sentinel, so an over-permissive target cannot pass acceptance off as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(f"expected head_object to fail with 404, but it succeeded: {result!r}")


_SKLEARN_REGISTRY = {
    "af-south-1": "455444449433",
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
    "eu-south-1": "978288397137",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-west-3": "659782779980",
    "me-south-1": "801668240914",
    "sa-east-1": "737474898029",
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
}


def _resolve_sklearn_image(ctx, scope: str = "inference") -> str:
    """Resolve the region-specific built-in scikit-learn container image URI directly
    from the known public ECR registry-account mapping, with no dependency on the
    sagemaker Python SDK being installed."""
    account = _SKLEARN_REGISTRY.get(ctx.region)
    if not account:
        raise AssertionError(f"no known scikit-learn built-in container registry for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_sagemaker_role(ctx, bucket: str, allow_put: bool) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    actions = ["s3:GetObject", "s3:ListBucket"]
    if allow_put:
        actions.append("s3:PutObject")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                ],
                "Resource": "*",
            },
        ],
    }
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_with_role_retry(ctx, create_fn, timeout_s: float = 150.0, interval_s: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return create_fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            role_prop_markers = ("not authorized", "could not assume role", "could not access model data")
            if code == "ValidationException" and any(m in msg.lower() for m in role_prop_markers):
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _run_processing_job(ctx, bucket: str, image_uri: str, role_arn: str, prefix: str) -> str:
    sm = ctx.client("sagemaker")
    job_name = ctx.unique_name(f"sim2real-sm-proc-{prefix}-")
    _create_with_role_retry(
        ctx,
        lambda: sm.create_processing_job(
            ProcessingJobName=job_name,
            RoleArn=role_arn,
            AppSpecification={
                "ImageUri": image_uri,
                "ContainerEntrypoint": ["python3", "/opt/ml/processing/input/code/process.py"],
            },
            ProcessingInputs=[
                {
                    "InputName": "code",
                    "S3Input": {
                        "S3Uri": f"s3://{bucket}/code/process.py",
                        "LocalPath": "/opt/ml/processing/input/code",
                        "S3DataType": "S3Prefix",
                        "S3InputMode": "File",
                    },
                }
            ],
            ProcessingOutputConfig={
                "Outputs": [
                    {
                        "OutputName": "results",
                        "S3Output": {
                            "S3Uri": f"s3://{bucket}/{prefix}/output/",
                            "LocalPath": "/opt/ml/processing/output/results",
                            "S3UploadMode": "EndOfJob",
                        },
                    }
                ]
            },
            ProcessingResources={
                "ClusterConfig": {"InstanceCount": 1, "InstanceType": "ml.m5.large", "VolumeSizeInGB": 5}
            },
            StoppingCondition={"MaxRuntimeInSeconds": 1200},
        ),
    )
    ctx.on_cleanup(lambda: _stop_processing_job_quiet(ctx, job_name))
    return job_name


def _wait_for_processing_job(ctx, job_name: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sm.describe_processing_job(ProcessingJobName=job_name)
        if desc["ProcessingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"processing job {job_name} did not reach a terminal state within {timeout_s}s: {desc}")


def _stop_processing_job_quiet(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        desc = sm.describe_processing_job(ProcessingJobName=job_name)
        if desc["ProcessingJobStatus"] == "InProgress":
            sm.stop_processing_job(ProcessingJobName=job_name)
    except ClientError as exc:
        if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_processing_job(ProcessingJobName=job_name)["ProcessingJobStatus"] == "InProgress"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
