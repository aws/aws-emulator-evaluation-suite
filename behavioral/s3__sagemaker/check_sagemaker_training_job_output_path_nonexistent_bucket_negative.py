"""sagemaker-training-job-output-path-nonexistent-bucket-negative."""
from __future__ import annotations

import json
import random
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-training-job-output-path-nonexistent-bucket-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A training job whose OutputDataConfig points at a bucket that was never created
    fails (it can read its real input fine, but cannot upload the artifact) while an
    identical job pointed at a real, existing bucket completes and writes its artifact."""
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_xgb_csv(60, seed=6).encode("utf-8"))
    role_arn = _create_execution_role(ctx, [f"arn:aws:s3:::{bucket}"])
    image = _resolve_algo_image(ctx, "xgboost", "1")

    nonexistent_bucket = _name(ctx, "nope-bkt")  # deliberately never created

    def _job(name: str, output_s3_uri: str) -> None:
        _create_training_job_with_retry(
            sm,
            TrainingJobName=name,
            AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{bucket}/train/",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                    "ContentType": "text/csv",
                    "CompressionType": "None",
                }
            ],
            OutputDataConfig={"S3OutputPath": output_s3_uri},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 900},
            HyperParameters={"num_round": "10", "objective": "binary:logistic"},
            Tags=[{"Key": "sim2real", "Value": "output-path-nonexistent-bucket"}],
        )
        ctx.on_cleanup(lambda n=name: _best_effort_stop(sm, n))

    job_ok = _name(ctx, "outpath-ok")
    _job(job_ok, f"s3://{bucket}/output-ok/")

    job_bad = _name(ctx, "outpath-bad")
    _job(job_bad, f"s3://{nonexistent_bucket}/output/")

    desc_ok = _wait_for_terminal(sm, job_ok, timeout_s=900, interval_s=15)
    desc_bad = _wait_for_terminal(sm, job_bad, timeout_s=900, interval_s=15)

    assert desc_ok["TrainingJobStatus"] == "Completed", (
        f"positive control did not complete: {desc_ok.get('FailureReason')}"
    )
    ok_bucket, ok_key = _parse_s3_uri(desc_ok["ModelArtifacts"]["S3ModelArtifacts"])
    assert _object_exists(ctx, ok_bucket, ok_key), "positive control did not write its model artifact"

    assert desc_bad["TrainingJobStatus"] == "Failed", (
        f"job with a nonexistent output bucket should fail, got {desc_bad['TrainingJobStatus']}"
    )
    assert desc_bad.get("FailureReason"), "expected a non-empty failure reason"
    assert not _bucket_exists(ctx, nonexistent_bucket), (
        "SageMaker must not have silently created the missing output bucket"
    )


# ===== helpers =====
_PREFIX = "sim2real-smk-"

_BUILTIN_ALGO_ACCOUNTS = {
    "us-east-1": "811284229777",
    "us-east-2": "825641698319",
    "us-west-1": "632365934929",
    "us-west-2": "433757028032",
    "ap-northeast-1": "501404015308",
    "ap-northeast-2": "306986355934",
    "ap-south-1": "991648021394",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "544295431143",
    "ca-central-1": "469771592824",
    "eu-central-1": "813361260812",
    "eu-north-1": "669576153137",
    "eu-west-1": "685385470294",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "sa-east-1": "855470959533",
}


def _name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _xgb_csv(n: int, seed: int = 0) -> str:
    rnd = random.Random(seed)
    lines = []
    for i in range(n):
        label = i % 2
        f1 = rnd.uniform(0, 1) + label * 2
        f2 = rnd.uniform(0, 1) + label * 2
        lines.append(f"{label},{f1:.4f},{f2:.4f}")
    return "\n".join(lines) + "\n"


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    assert uri.startswith("s3://"), f"expected an s3:// URI, got {uri!r}"
    rest = uri[len("s3://") :]
    bucket, _, key = rest.partition("/")
    return bucket, key


def _object_exists(ctx: Any, bucket: str, key: str) -> bool:
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise


def _bucket_exists(ctx: Any, bucket: str) -> bool:
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    try:
        s3.head_bucket(Bucket=bucket)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchBucket"):
            return False
        raise


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = _name(ctx, "bkt")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "output-path-nonexistent-bucket"}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=name, Key=o["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_execution_role(ctx: Any, bucket_arns: list[str], allow_s3: bool = True) -> str:
    iam = ctx.client("iam")
    role_name = _name(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "output-path-nonexistent-bucket"}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            "Resource": "*",
        }
    ]
    if allow_s3:
        resources: list[str] = []
        for arn in bucket_arns:
            resources.append(arn)
            resources.append(arn + "/*")
        statements.append({"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], "Resource": resources})

    policy_name = _name(ctx, "policy")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    iam.delete_role(RoleName=role_name)


def _resolve_algo_image(ctx: Any, algo: str, tag: str) -> str:
    account = _BUILTIN_ALGO_ACCOUNTS.get(ctx.region)
    if not account:
        raise AssertionError(f"no known built-in-algorithm ECR account for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/{algo}:{tag}"


def _create_training_job_with_retry(sm, timeout_s: float = 120, poll_s: float = 10, **kwargs) -> dict:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            role_propagation = "trust" in msg or "assume role" in msg or "not authorized" in msg
            if code == "ValidationException" and role_propagation and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise


def _wait_for_terminal(sm, job_name: str, timeout_s: float = 900, interval_s: float = 15) -> dict:
    terminal = {"Completed", "Failed", "Stopped"}
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        last = sm.describe_training_job(TrainingJobName=job_name)
        if last["TrainingJobStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"training job {job_name} did not reach a terminal state in {timeout_s}s "
        f"(last status={last['TrainingJobStatus'] if last else None})"
    )


def _best_effort_stop(sm, job_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
