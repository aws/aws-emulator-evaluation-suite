"""sagemaker-execution-role-s3-bucket-policy-denies-access-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-execution-role-s3-bucket-policy-denies-access-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]

# AWS's own SageMaker built-in-algorithm ECR registry owner account per region - a fixed,
# non-adjustable constant AWS publishes (not a per-account setting), used only as a fallback
# when the `sagemaker` SDK is unavailable to resolve the XGBoost image URI locally.
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


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bucket policy Deny on s3:GetObject for one role's ARN fails that role's training job with no
    artifact, while an identically allowed role not named in the Deny trains to completion."""
    image_uri = _resolve_algo_image(ctx)
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")

    bucket = ctx.unique_name("sim2real-sm-bucketdeny-")
    _create_bucket(ctx, s3, bucket)
    _upload_training_csv(s3, bucket, "train/train.csv")

    s3_statements = [{
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
    }]
    allowed_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-sm-allowed-"), s3_statements
    )
    denied_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-sm-denied-"), s3_statements
    )

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyOneRoleReadAccess",
            "Effect": "Deny",
            "Principal": {"AWS": denied_role_arn},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/train/*",
        }],
    }
    _put_bucket_policy_with_retry(s3, bucket, bucket_policy)
    ctx.on_cleanup(lambda: _delete_bucket_policy(s3, bucket))
    _wait_bucket_policy_visible(s3, bucket, bucket_policy)

    allowed_job = ctx.unique_name("sim2real-sm-allowed-job-")
    _launch_training_job(sm, allowed_job, image_uri, allowed_role_arn, bucket, "output-allowed/")
    ctx.on_cleanup(lambda: _best_effort_stop_training(sm, allowed_job))

    denied_job = ctx.unique_name("sim2real-sm-denied-job-")
    _launch_training_job(sm, denied_job, image_uri, denied_role_arn, bucket, "output-denied/")
    ctx.on_cleanup(lambda: _best_effort_stop_training(sm, denied_job))

    denied_desc = _wait_training_terminal(sm, denied_job, timeout_s=900)
    assert denied_desc["TrainingJobStatus"] == "Failed", (
        "a training job whose role is explicitly Denied s3:GetObject by the bucket "
        f"policy was expected to fail, got status {denied_desc['TrainingJobStatus']!r}"
    )
    denied_listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"output-denied/{denied_job}/")
    assert "Contents" not in denied_listing, (
        f"denied-role job wrote output despite the explicit bucket-policy Deny: "
        f"{denied_listing.get('Contents')}"
    )

    allowed_desc = _wait_training_terminal(sm, allowed_job, timeout_s=1200)
    assert allowed_desc["TrainingJobStatus"] == "Completed", (
        f"positive control (role not named in the Deny statement) failed to complete: "
        f"{allowed_desc.get('FailureReason')}"
    )
    allowed_listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"output-allowed/{allowed_job}/output/")
    allowed_keys = [o["Key"] for o in allowed_listing.get("Contents", [])]
    assert any(k.endswith("model.tar.gz") for k in allowed_keys), (
        f"positive control completed but produced no model artifact: {allowed_keys}"
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


def _create_bucket(ctx: Any, s3: Any, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))


def _delete_bucket_policy(s3: Any, bucket: str) -> None:
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _put_bucket_policy_with_retry(
    s3: Any, bucket: str, policy: dict, timeout_s: float = 60, poll_s: float = 5
) -> None:
    """A bucket policy whose Principal names an IAM role created moments ago can be
    rejected with MalformedPolicy/'Invalid principal in policy' until that role has
    propagated through IAM; retry the PutBucketPolicy call (not the role creation)
    since that is the exact API call being validated against the new principal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            if code == "MalformedPolicy" and "principal" in msg and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise


def _wait_bucket_policy_visible(
    s3: Any, bucket: str, expected_policy: dict, timeout_s: float = 60, poll_s: float = 3
) -> None:
    """A bucket-policy write can lag a follow-on GetBucketPolicy by a few seconds; poll this
    same client until it reads back the exact policy just written, instead of guessing a sleep
    duration for a propagation delay that a fixed sleep cannot actually bound."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            current = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        except Exception:
            current = None
        if current == expected_policy:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"bucket policy for {bucket!r} never became visible via GetBucketPolicy "
                f"within {timeout_s}s; last read: {current!r}"
            )
        time.sleep(poll_s)


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


def _create_role(ctx: Any, iam: Any, role_name: str, s3_statements: list) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _launch_training_job(
    sm: Any, job_name: str, image_uri: str, role_arn: str, bucket: str, output_prefix: str
) -> None:
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
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/{output_prefix}"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={"objective": "reg:linear", "num_round": "5"},
    )


def _create_training_job_with_retry(sm: Any, timeout_s: float = 60, poll_s: float = 10, **kwargs) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            role_propagation = "assume role" in msg or "not authorized" in msg
            if code == "ValidationException" and role_propagation and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise


def _wait_training_terminal(sm: Any, job_name: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        if desc["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"training job {job_name} never reached a terminal state: {desc}")


def _best_effort_stop_training(sm: Any, job_name: str) -> None:
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

