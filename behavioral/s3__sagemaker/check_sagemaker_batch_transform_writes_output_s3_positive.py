"""sagemaker-batch-transform-writes-output-s3-positive."""
from __future__ import annotations

import io
import json
import random
import string
import tarfile
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-batch-transform-writes-output-s3-positive"
GROUP = "artifact-delivery"
SERVICES = ["s3", "sagemaker"]

_INFERENCE_SCRIPT = """
def model_fn(model_dir):
    return {}


def input_fn(input_data, content_type):
    if isinstance(input_data, bytes):
        return input_data.decode("utf-8")
    return input_data


def predict_fn(input_data, model):
    return input_data.strip().upper()


def output_fn(prediction, accept):
    return prediction + "\\n", "text/plain"
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Batch Transform inference results are written to the exact S3 destination named
    in TransformOutput.S3OutputPath, using the documented "<input-filename>.out" naming
    convention, and only after the job completes."""
    image_uri = _resolve_sklearn_image(ctx)
    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, bucket, allow_put=True)
    s3 = ctx.client("s3")
    output_key = "transform/output/payload.csv.out"

    code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=output_key))
    assert code == "404", f"expected transform output to not exist yet, got code {code}"

    marker = "".join(random.choices(string.ascii_lowercase, k=10))
    s3.put_object(Bucket=bucket, Key="transform/input/payload.csv", Body=(marker + "\n").encode())
    s3.put_object(Bucket=bucket, Key="model/model.tar.gz", Body=_build_model_tar(_INFERENCE_SCRIPT))

    model_name = _create_model(ctx, bucket, image_uri, role_arn, "model/model.tar.gz")

    job_name = ctx.unique_name("sim2real-sm-bt-out-")
    sm = ctx.client("sagemaker")
    _create_with_role_retry(
        ctx,
        lambda: sm.create_transform_job(
            TransformJobName=job_name,
            ModelName=model_name,
            BatchStrategy="SingleRecord",
            TransformInput={
                "DataSource": {
                    "S3DataSource": {"S3DataType": "S3Prefix", "S3Uri": f"s3://{bucket}/transform/input/"}
                },
                "ContentType": "text/plain",
                "SplitType": "Line",
            },
            TransformOutput={
                "S3OutputPath": f"s3://{bucket}/transform/output/",
                "AssembleWith": "Line",
                "Accept": "text/plain",
            },
            TransformResources={"InstanceType": "ml.m5.large", "InstanceCount": 1},
            Tags=[{"Key": "sim2real", "Value": "batch-transform-output"}],
        ),
    )
    ctx.on_cleanup(lambda: _stop_transform_job_quiet(ctx, job_name))

    desc = _wait_for_transform_job(ctx, job_name)
    assert desc["TransformJobStatus"] == "Completed", desc.get("FailureReason")

    obj = s3.get_object(Bucket=bucket, Key=output_key)
    body = obj["Body"].read().decode()
    assert marker.upper() in body, f"expected transformed marker {marker.upper()!r} in output body, got {body!r}"
    # nothing else under the output prefix - delivery landed exactly at the configured path
    listed = s3.list_objects_v2(Bucket=bucket, Prefix="transform/output/")
    keys = [o["Key"] for o in listed.get("Contents", [])]
    assert keys == [output_key], keys


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
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _build_model_tar(script_text: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = script_text.encode("utf-8")
        info = tarfile.TarInfo(name="code/inference.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


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

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_sagemaker_role(ctx, bucket: str, allow_put: bool = True) -> str:
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
        Tags=[{"Key": "sim2real", "Value": "batch-transform-output"}],
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


def _create_model(ctx, bucket: str, image_uri: str, role_arn: str, model_key: str) -> str:
    sm = ctx.client("sagemaker")
    model_name = ctx.unique_name("sim2real-sm-model-")
    _create_with_role_retry(
        ctx,
        lambda: sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={
                "Image": image_uri,
                "ModelDataUrl": f"s3://{bucket}/{model_key}",
                "Environment": {
                    "SAGEMAKER_PROGRAM": "inference.py",
                    "SAGEMAKER_SUBMIT_DIRECTORY": "/opt/ml/model/code",
                },
            },
            Tags=[{"Key": "sim2real", "Value": "batch-transform-output"}],
        ),
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))
    return model_name


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


def _wait_for_transform_job(ctx, job_name: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sm.describe_transform_job(TransformJobName=job_name)
        if desc["TransformJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"transform job {job_name} did not reach a terminal state within {timeout_s}s: {desc}")


def _stop_transform_job_quiet(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        desc = sm.describe_transform_job(TransformJobName=job_name)
        if desc["TransformJobStatus"] == "InProgress":
            sm.stop_transform_job(TransformJobName=job_name)
    except ClientError as exc:
        if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_transform_job(TransformJobName=job_name)["TransformJobStatus"] == "InProgress"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
