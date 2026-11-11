"""sagemaker-training-job-s3-input-manifest-format-positive."""
from __future__ import annotations

import json
import random
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-training-job-s3-input-manifest-format-positive"
GROUP = "data-format"
SERVICES = ["s3", "sagemaker"]

# Registry account IDs for the SageMaker built-in "blazingtext" algorithm
# container, keyed by region.
_BLAZINGTEXT_REGISTRY = {
    "us-east-1": "811284229777",
    "us-east-2": "825641698319",
    "us-west-1": "632365934929",
    "us-west-2": "433757028032",
    "eu-west-1": "685385470294",
    "eu-central-1": "813361260812",
    "ap-northeast-1": "501404015308",
    "ap-northeast-2": "306986355934",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "544295431143",
    "ap-south-1": "991648021394",
    "ca-central-1": "469771592824",
    "sa-east-1": "855470959533",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BlazingText job on an AugmentedManifestFile input in Pipe mode with
    AttributeNames ["source", "label"] parses the JSON lines and maps the attributes,
    so it reports a training accuracy metric rather than failing."""
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="manifest/train.jsonl", Body=_augmented_manifest_lines(60))

    role_arn = _create_execution_role(
        ctx,
        statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/output/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    )

    image = _builtin_image_uri(ctx, "blazingtext", "1", _BLAZINGTEXT_REGISTRY)
    job_name = ctx.unique_name("sim2real-sm-manifest-")
    ctx.on_cleanup(lambda: _stop_training_job_if_running(ctx, sm, job_name))

    _create_training_job_with_retry(
        sm,
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "Pipe"},
        RoleArn=role_arn,
        InputDataConfig=[
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "AugmentedManifestFile",
                        "S3Uri": f"s3://{bucket}/manifest/train.jsonl",
                        "S3DataDistributionType": "FullyReplicated",
                        "AttributeNames": ["source", "label"],
                    }
                },
                "RecordWrapperType": "RecordIO",
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={
            "mode": "supervised",
            "epochs": "5",
            "min_count": "1",
            "word_ngrams": "1",
            "vector_dim": "10",
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    desc = _wait_training_job_terminal(sm, job_name, timeout_s=900)
    assert desc["TrainingJobStatus"] == "Completed", desc.get("FailureReason")
    metrics = {m["MetricName"]: m["Value"] for m in desc.get("FinalMetricDataList", [])}
    assert "train:accuracy" in metrics, (
        f"expected train:accuracy from records built out of the manifest's mapped "
        f"attributes, got {list(metrics)}"
    )


# ===== helpers =====

def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=name, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _augmented_manifest_lines(n: int, seed: int = 99) -> bytes:
    rnd = random.Random(seed)
    cat_words = ["cat", "kitten", "feline", "whiskers", "purring", "meow"]
    dog_words = ["dog", "puppy", "canine", "bark", "fetch", "woof"]
    lines = []
    for i in range(n):
        if i % 2 == 0:
            words = rnd.sample(cat_words, 3)
            label = 1
        else:
            words = rnd.sample(dog_words, 3)
            label = 2
        lines.append(json.dumps({"source": " ".join(words), "label": label}))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _create_execution_role(ctx, *, statements: list[dict[str, Any]], trust_service: str = "sagemaker.amazonaws.com") -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_name = f"{name}-policy"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _builtin_image_uri(ctx, repo: str, tag: str, registry: dict[str, str]) -> str:
    account = registry.get(ctx.region)
    if account is None:
        raise AssertionError(f"no known {repo} built-in-algorithm registry account for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/{repo}:{tag}"


def _create_training_job_with_retry(sm, *, timeout_s: int = 90, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume role" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_training_job_terminal(sm, name: str, timeout_s: int = 900, poll_s: int = 15) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=name)
        if desc["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(poll_s)
    raise AssertionError(f"training job {name} did not reach terminal state within {timeout_s}s: {desc}")


def _stop_training_job_if_running(ctx, sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        desc = sm.describe_training_job(TrainingJobName=name)
    except ClientError as e:
        # A job whose create call was refused does not exist; any other error is a failure.
        err = e.response["Error"]
        if err["Code"] == "ValidationException" and "not found" in err.get("Message", "").lower():
            return
        raise
    if desc["TrainingJobStatus"] != "InProgress":
        return
    try:
        sm.stop_training_job(TrainingJobName=name)
    except ClientError as exc:
        # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] == "InProgress":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
