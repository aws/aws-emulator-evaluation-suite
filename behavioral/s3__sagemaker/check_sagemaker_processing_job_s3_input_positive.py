"""sagemaker-processing-job-s3-input-positive."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-processing-job-s3-input-positive"
GROUP = "processing-io"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateProcessingJob ProcessingInput S3Uri correctly stages an S3 object's exact
    bytes into the processing container (verified via a deterministic transform)."""
    image_uri = _resolve_sklearn_processing_image(ctx)
    bucket = _create_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    marker = ctx.unique_name("payload-")
    s3.put_object(Bucket=bucket, Key="input/data.txt", Body=marker.encode())

    script = (
        "import pathlib\n"
        "src = pathlib.Path('/opt/ml/processing/input')\n"
        "dst = pathlib.Path('/opt/ml/processing/output')\n"
        "dst.mkdir(parents=True, exist_ok=True)\n"
        "for f in sorted(src.iterdir()):\n"
        "    (dst / (f.name + '.out')).write_text(f.read_text().upper())\n"
    )
    inputs = [
        {
            "InputName": "input-1",
            "S3Input": {
                "S3Uri": f"s3://{bucket}/input/",
                "LocalPath": "/opt/ml/processing/input",
                "S3DataType": "S3Prefix",
                "S3InputMode": "File",
                "S3DataDistributionType": "FullyReplicated",
            },
        }
    ]
    outputs = [
        {
            "OutputName": "output-1",
            "S3Output": {
                "S3Uri": f"s3://{bucket}/output/",
                "LocalPath": "/opt/ml/processing/output",
                "S3UploadMode": "EndOfJob",
            },
        }
    ]

    job = _run_processing_job(
        ctx, sm, s3, bucket, role_arn=role_arn, image_uri=image_uri, script=script, inputs=inputs, outputs=outputs
    )
    final = _wait_processing_job(sm, job)
    assert final["ProcessingJobStatus"] == "Completed", final.get("FailureReason")

    body = s3.get_object(Bucket=bucket, Key="output/data.txt.out")["Body"].read().decode()
    assert body == marker.upper(), "container did not receive the exact S3 input bytes"


# ===== helpers =====


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "RepositoryNotFoundException") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "processing-job-s3-input"}]})

    def _cleanup():
        objs = [{"Key": o["Key"]} for o in s3.list_objects_v2(Bucket=name).get("Contents", [])]
        for i in range(0, len(objs), 1000):
            batch = objs[i : i + 1000]
            if batch:
                s3.delete_objects(Bucket=name, Delete={"Objects": batch})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_execution_role(ctx, bucket, *, allow_get=True, allow_put=True, kms_key_arn=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "processing-job-s3-input"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    s3_actions = ["s3:ListBucket"]
    if allow_get:
        s3_actions.append("s3:GetObject")
    if allow_put:
        s3_actions.append("s3:PutObject")
    statements = [
        {
            "Effect": "Allow",
            "Action": s3_actions,
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            "Resource": "arn:aws:logs:*:*:*",
        },
    ]
    if kms_key_arn:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
                "Resource": kms_key_arn,
            }
        )
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _retry_role_propagation(fn, *, timeout_s=120.0, interval_s=5.0):
    # A freshly created IAM role/policy is eventually consistent; SageMaker's own
    # AssumeRole check on job creation can transiently fail for tens of seconds.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last}")


_FRAMEWORK_ECR_ACCOUNT_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ca-central-1": "341280168497",
    "sa-east-1": "737474898029",
}


def _resolve_sklearn_processing_image(ctx):
    # AWS-owned "sagemaker-scikit-learn" framework container registry paths are
    # publicly documented (see AWS docs "Accessing Docker Images for Scikit-learn and
    # Spark ML") — hardcoded here since the 'sagemaker' Python SDK isn't installed.
    account = _FRAMEWORK_ECR_ACCOUNT_BY_REGION.get(ctx.region)
    if not account:
        raise AssertionError(f"no known AWS-owned scikit-learn container account ID for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"


def _run_processing_job(ctx, sm, s3, bucket, *, role_arn, image_uri, script, inputs, outputs, kms_key_id=None):
    name = ctx.unique_name("sim2real-sm-proc-")
    output_config = {"Outputs": outputs}
    if kms_key_id:
        output_config["KmsKeyId"] = kms_key_id

    # CreateProcessingJob's ContainerEntrypoint elements are capped at 256 chars each — far
    # too short to inline a real script. Stage it in S3 instead and have a short bootstrap
    # one-liner fetch + exec it (the execution role already has s3:GetObject on this bucket).
    script_key = f"_bootstrap/{name}.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=script.encode())
    bootstrap = (
        f"import boto3;boto3.client('s3').download_file('{bucket}','{script_key}','/tmp/s.py');"
        "exec(open('/tmp/s.py').read())"
    )
    assert len(bootstrap) <= 256, f"bootstrap one-liner too long ({len(bootstrap)} chars)"

    def _create():
        sm.create_processing_job(
            ProcessingJobName=name,
            RoleArn=role_arn,
            AppSpecification={"ImageUri": image_uri, "ContainerEntrypoint": ["python3", "-c", bootstrap]},
            ProcessingInputs=inputs,
            ProcessingOutputConfig=output_config,
            ProcessingResources={
                "ClusterConfig": {"InstanceCount": 1, "InstanceType": "ml.m5.large", "VolumeSizeInGB": 5}
            },
            StoppingCondition={"MaxRuntimeInSeconds": 900},
        )

    _retry_role_propagation(_create)
    ctx.on_cleanup(lambda: _stop_processing_job(sm, name))
    return name


def _stop_processing_job(sm, name):
    try:
        status = sm.describe_processing_job(ProcessingJobName=name)["ProcessingJobStatus"]
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    if status == "InProgress":
        try:
            sm.stop_processing_job(ProcessingJobName=name)
        except ClientError as exc:
            if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_processing_job(ProcessingJobName=name)["ProcessingJobStatus"] == "InProgress"):
                raise


def _wait_processing_job(sm, name, *, timeout_s=900.0):
    return _poll_until(
        lambda: sm.describe_processing_job(ProcessingJobName=name),
        lambda r: r["ProcessingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=timeout_s,
        interval_s=8.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
