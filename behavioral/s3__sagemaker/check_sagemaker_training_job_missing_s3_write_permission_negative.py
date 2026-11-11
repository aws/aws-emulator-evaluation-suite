"""sagemaker-training-job-missing-s3-write-permission-negative."""
from __future__ import annotations

import json
import random
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-training-job-missing-s3-write-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]

# AWS-published account that owns the built-in XGBoost algorithm image repo in each
# region; a fixed per-region constant, not an assumption about which region this runs in.
_XGBOOST_REGISTRY = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "685385470294",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "eu-central-1": "813361260812",
    "eu-north-1": "669576153137",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-south-1": "720646828776",
    "ca-central-1": "341280168497",
    "sa-east-1": "855470959533",
}


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A training job whose role can read its input but lacks s3:PutObject on the output
    prefix fails at upload with an access-denied reason and writes no artifact, while
    an otherwise-identical job with write access completes and writes one."""
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="train/data.csv", Body=_training_csv_bytes(150))
    image = _builtin_image_uri(ctx, "sagemaker-xgboost", "1.7-1", _XGBOOST_REGISTRY)

    read_stmt = {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
    }
    logs_stmt = {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
        "Resource": "arn:aws:logs:*:*:*",
    }

    # Role with read access but NO s3:PutObject anywhere.
    role_bad = _create_execution_role(ctx, statements=[read_stmt, logs_stmt])
    # Positive control: read + write.
    role_good = _create_execution_role(
        ctx,
        statements=[
            read_stmt,
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket}/output-good/*"]},
            logs_stmt,
        ],
    )

    job_bad = ctx.unique_name("sim2real-sm-wrneg-")
    job_good = ctx.unique_name("sim2real-sm-wrok-")
    ctx.on_cleanup(lambda: _stop_training_job_if_running(ctx, sm, job_bad))
    ctx.on_cleanup(lambda: _stop_training_job_if_running(ctx, sm, job_good))

    def _job_kwargs(name: str, role_arn: str, out_prefix: str) -> dict[str, Any]:
        return dict(
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
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/{out_prefix}/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 900},
            HyperParameters={"objective": "reg:squarederror", "num_round": "10"},
            Tags=[{"Key": "sim2real", "Value": "s3-write-permission"}],
        )

    _create_training_job_with_retry(sm, **_job_kwargs(job_bad, role_bad, "output-bad"))
    _create_training_job_with_retry(sm, **_job_kwargs(job_good, role_good, "output-good"))

    descs = _wait_training_jobs_terminal(sm, [job_bad, job_good], timeout_s=900)

    desc_bad = descs[job_bad]
    assert desc_bad["TrainingJobStatus"] == "Failed", (
        f"expected job_bad TrainingJobStatus=Failed, got {desc_bad['TrainingJobStatus']!r} "
        f"(failure_reason={desc_bad.get('FailureReason')!r})"
    )
    reason = desc_bad.get("FailureReason", "")
    assert "not authorized" in reason.lower() or "access denied" in reason.lower(), (
        f"expected an access-denied failure reason, got: {reason}"
    )
    bad_out = s3.list_objects_v2(Bucket=bucket, Prefix="output-bad/")
    assert not bad_out.get("Contents"), "no model artifact should have been written without write access"

    desc_good = descs[job_good]
    assert desc_good["TrainingJobStatus"] == "Completed", (
        f"expected job_good TrainingJobStatus=Completed, got {desc_good['TrainingJobStatus']!r} "
        f"(failure_reason={desc_good.get('FailureReason')!r})"
    )
    good_out = s3.list_objects_v2(Bucket=bucket, Prefix="output-good/")
    assert any(o["Key"].endswith("model.tar.gz") for o in good_out.get("Contents", [])), (
        "positive control did not produce a model artifact"
    )


# ===== helpers =====

def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "s3-write-permission"}]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=name, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _training_csv_bytes(n_rows: int, seed: int = 1234) -> bytes:
    rnd = random.Random(seed)
    lines = []
    for _ in range(n_rows):
        f1, f2, f3 = rnd.uniform(0, 10), rnd.uniform(0, 10), rnd.uniform(0, 10)
        label = 2.0 * f1 - 1.5 * f2 + 0.5 * f3 + rnd.uniform(-0.1, 0.1)
        lines.append(f"{label:.4f},{f1:.4f},{f2:.4f},{f3:.4f}")
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
        Tags=[{"Key": "sim2real", "Value": "s3-write-permission"}],
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


def _wait_training_jobs_terminal(sm, names: list[str], timeout_s: int = 900, poll_s: int = 15) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    final: dict[str, Any] = {}
    pending = set(names)
    while pending and time.monotonic() < deadline:
        for name in list(pending):
            desc = sm.describe_training_job(TrainingJobName=name)
            if desc["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
                final[name] = desc
                pending.discard(name)
        if pending:
            time.sleep(poll_s)
    if pending:
        raise AssertionError(f"training jobs {pending} did not reach terminal state within {timeout_s}s")
    return final


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
