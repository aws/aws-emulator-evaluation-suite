"""sagemaker-create-role-trusts-sagemaker-service-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-create-role-trusts-sagemaker-service-positive"
GROUP = "iam-trust"
SERVICES = ["s3", "sagemaker"]

# AWS's own fixed per-region ECR registry accounts for the SageMaker built-in XGBoost
# algorithm image; identical for every caller in a region, not an account-specific value.
_XGBOOST_ACCOUNTS = {
    "us-east-1": "811284229777",
    "us-east-2": "825641698319",
    "us-west-1": "632365934929",
    "us-west-2": "433757028032",
    "eu-west-1": "685385470294",
    "eu-central-1": "813361260812",
    "ap-northeast-1": "501404015308",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "544295431143",
    "ca-central-1": "469771592824",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting sagemaker.amazonaws.com, scoped to an S3 prefix, lets a training job read its
    input from that prefix and write a model artifact back with the role's own credentials."""
    image_uri = _resolve_algo_image(ctx)
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")

    bucket = ctx.unique_name("sim2real-sm-iamtrust-")
    _create_bucket(ctx, s3, bucket)
    _upload_training_csv(s3, bucket, "train/train.csv")

    role_name = ctx.unique_name("sim2real-sm-role-")
    role_arn = _create_role(
        ctx,
        iam,
        role_name,
        trust_services="sagemaker.amazonaws.com",
        s3_statements=[{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    )
    # IAM role/policy changes take a few seconds to propagate globally before every
    # service endpoint can honor sts:AssumeRole; _create_training_job_with_retry's
    # bounded retry on the role-propagation ValidationException absorbs that delay,
    # so no fixed pause belongs here.
    job_name = ctx.unique_name("sim2real-sm-job-")
    _create_training_job_with_retry(
        sm,
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        InputDataConfig=[{
            "ChannelName": "train",
            "DataSource": {"S3DataSource": {
                "S3DataType": "S3Prefix",
                "S3Uri": f"s3://{bucket}/train/",
                "S3DataDistributionType": "FullyReplicated",
            }},
            "ContentType": "text/csv",
        }],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={"objective": "reg:linear", "num_round": "5"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort_stop(sm, job_name))

    desc = _wait_training_terminal(sm, job_name, timeout_s=1200)
    assert desc["TrainingJobStatus"] == "Completed", (
        f"training job did not complete via the trusted role: {desc.get('FailureReason')}"
    )
    listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"output/{job_name}/output/")
    keys = [o["Key"] for o in listing.get("Contents", [])]
    assert any(k.endswith("model.tar.gz") for k in keys), (
        f"training job completed but wrote no model artifact under its output prefix: {keys}"
    )


# ===== helpers =====

def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "RepositoryNotFoundException") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
    )


def _resolve_algo_image(ctx: Any, algo: str = "xgboost", tag: str = "1") -> str:
    try:
        from sagemaker import image_uris  # type: ignore

        return image_uris.retrieve(algo, ctx.region, version=tag)
    except Exception:
        pass

    account = _XGBOOST_ACCOUNTS.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no known SageMaker built-in XGBoost algorithm registry account mapped for "
            f"region {ctx.region!r} in this check - add it to close the gap"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/{algo}:{tag}"


def _create_training_job_with_retry(sm: Any, timeout_s: float = 120, poll_s: float = 10, **kwargs) -> dict:
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


def _create_bucket(ctx: Any, s3: Any, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _delete_bucket(s3: Any, bucket: str) -> None:
    try:
        while True:
            resp = s3.list_objects_v2(Bucket=bucket)
            contents = resp.get("Contents", [])
            if not contents:
                break
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            )
            if not resp.get("IsTruncated"):
                break
    except ClientError as exc:
        if not _gone(exc):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _upload_training_csv(s3: Any, bucket: str, key: str, n_rows: int = 60) -> None:
    import random

    rng = random.Random(42)
    lines = []
    for _ in range(n_rows):
        f1 = rng.uniform(0, 10)
        f2 = rng.uniform(0, 10)
        label = 2.0 * f1 + 3.0 * f2 + rng.uniform(-0.5, 0.5)
        lines.append(f"{label:.4f},{f1:.4f},{f2:.4f}")
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(lines).encode("utf-8"))


def _create_role(
    ctx: Any, iam: Any, role_name: str, trust_services: Any, s3_statements: list
) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": trust_services},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": s3_statements}),
    )
    return role_arn


def _delete_role(iam: Any, role_name: str) -> None:
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if not _gone(exc):
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _wait_training_terminal(sm: Any, job_name: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        if desc["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"training job {job_name} never reached a terminal state: {desc}")


def _best_effort_stop(sm: Any, job_name: str) -> None:
    try:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        if desc["TrainingJobStatus"] in ("InProgress", "Stopping"):
            sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
