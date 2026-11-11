"""sagemaker-model-artifact-s3-uri-resolution-arn."""
from __future__ import annotations

import io
import tarfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-model-artifact-s3-uri-resolution-arn"
GROUP = "arn-resolution"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeTrainingJob's ModelArtifacts.S3ModelArtifacts is the model.tar.gz under the job's
    OutputDataConfig prefix, the only key the job wrote there, and the object is a readable non-empty
    tar.gz whose members are non-empty and expand past the compressed size."""
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(
        ctx,
        statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket}/*"]},
        ],
    )

    prefix = "model"
    job_name = _train_linear_learner_model(ctx, bucket, role_arn, prefix=prefix, return_job_name=True)
    desc = sm.describe_training_job(TrainingJobName=job_name)
    assert desc["TrainingJobStatus"] == "Completed", (
        f"expected training job {job_name!r} to complete, got status "
        f"{desc['TrainingJobStatus']!r} reason={desc.get('FailureReason')!r}"
    )

    s3_uri = desc["ModelArtifacts"]["S3ModelArtifacts"]
    assert s3_uri.startswith(f"s3://{bucket}/{prefix}/training-output/{job_name}/"), (
        f"model artifact URI {s3_uri!r} does not resolve under the configured output prefix"
    )
    assert s3_uri.endswith("model.tar.gz"), (
        f"expected model artifact URI to end with 'model.tar.gz', got {s3_uri!r}"
    )

    art_bucket, art_key = s3_uri[len("s3://") :].split("/", 1)
    head = s3.head_object(Bucket=art_bucket, Key=art_key)
    assert head["ContentLength"] > 0, "resolved model artifact object is empty"

    body = s3.get_object(Bucket=art_bucket, Key=art_key)["Body"].read()
    assert len(body) == head["ContentLength"], (
        f"fetched {len(body)} bytes but HeadObject reported ContentLength "
        f"{head['ContentLength']} for {art_key!r}"
    )
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        members = tar.getmembers()
        files = [m for m in members if m.isfile()]
        extracted = {}
        for member in files:
            handle = tar.extractfile(member)
            assert handle is not None, f"archive member {member.name!r} is not readable"
            extracted[member.name] = handle.read()
    assert files, (
        f"resolved model artifact opens as a tar.gz but has no file member: "
        f"{[(m.name, m.type) for m in members]!r}"
    )
    assert all(m.size > 0 for m in files), (
        f"resolved model artifact contains an empty file member: "
        f"{[(m.name, m.size) for m in files]!r}"
    )
    uncompressed = sum(len(extracted[m.name]) for m in files)
    assert uncompressed > len(body), (
        f"model archive does not actually decompress -- {uncompressed} uncompressed bytes from a "
        f"{len(body)}-byte archive, so it is not a real gzipped model archive: "
        f"{[(m.name, m.size) for m in files]!r}"
    )

    produced = sorted(
        o["Key"]
        for o in s3.list_objects_v2(
            Bucket=art_bucket, Prefix=f"{prefix}/training-output/{job_name}/"
        ).get("Contents", [])
    )
    assert produced == [art_key], (
        f"the job's output prefix must hold exactly the artifact it reported: {produced!r}, "
        f"expected [{art_key!r}]"
    )


# AWS-owned ECR registry account hosting the SageMaker built-in linear-learner algorithm image;
# one fixed account per region, not a resource in this account, so pinning it here is a region-pin
# on an AWS-global singleton, not an assumption about this account's resources.
LINEAR_LEARNER_ACCOUNT_BY_REGION = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
}
LINEAR_LEARNER_TAG = "1"

TRAIN_CSV = (
    "1.0,0.10,0.20\n"
    "2.0,0.20,0.30\n"
    "3.0,0.30,0.40\n"
    "4.0,0.40,0.50\n"
    "5.0,0.50,0.60\n"
    "6.0,0.60,0.70\n"
    "7.0,0.70,0.80\n"
    "8.0,0.80,0.90\n"
)


def _linear_learner_image(region: str) -> str:
    account = LINEAR_LEARNER_ACCOUNT_BY_REGION.get(region)
    if not account:
        raise AssertionError(
            f"no known linear-learner built-in-algorithm ECR account mapped for region {region}; "
            "extend LINEAR_LEARNER_ACCOUNT_BY_REGION to enable this check there"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:{LINEAR_LEARNER_TAG}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-s3-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_sagemaker_role(ctx, *, statements) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json_dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_name = ctx.unique_name("sim2real-sm-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=_json_dumps({"Version": "2012-10-17", "Statement": statements})
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _json_dumps(obj) -> str:
    import json

    return json.dumps(obj)


def _retry_role_not_ready(create_fn, *, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return create_fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s: float = 900.0, interval_s: float = 20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not reached within {timeout_s}s; last observed={last!r}")


def _wait_for_terminal(describe_fn, status_key, *, timeout_s: float = 900.0, interval_s: float = 20.0):
    terminal = {"Completed", "Failed", "Stopped"}
    return _poll_until(describe_fn, lambda resp: resp[status_key] in terminal, timeout_s=timeout_s, interval_s=interval_s)


def _train_linear_learner_model(ctx, bucket, role_arn, *, prefix="model", return_job_name=False):
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    s3.put_object(Bucket=bucket, Key=f"{prefix}/train/data.csv", Body=TRAIN_CSV.encode("utf-8"))
    job_name = ctx.unique_name(f"sim2real-sm-train-{prefix}-")
    image = _linear_learner_image(ctx.region)

    def _create():
        return sm.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{bucket}/{prefix}/train/",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                    "ContentType": "text/csv",
                    "CompressionType": "None",
                }
            ],
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/{prefix}/training-output/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 1800},
            HyperParameters={"predictor_type": "regressor", "mini_batch_size": "4"},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    _retry_role_not_ready(_create)
    desc = _wait_for_terminal(lambda: sm.describe_training_job(TrainingJobName=job_name), "TrainingJobStatus")
    if desc["TrainingJobStatus"] != "Completed":
        raise AssertionError(f"setup: linear-learner training job failed: {desc.get('FailureReason')}")
    if return_job_name:
        return job_name
    return desc["ModelArtifacts"]["S3ModelArtifacts"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
