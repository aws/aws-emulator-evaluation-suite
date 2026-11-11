"""sagemaker-trained-model-artifact-is-a-real-loadable-archive-at-the-uri-it-reports."""
from __future__ import annotations

import io
import json
import tarfile
import time
from urllib.parse import urlparse
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-trained-model-artifact-is-a-real-loadable-archive-at-the-uri-it-reports"
GROUP = 'training'
SERVICES = ['s3', 'sagemaker']

# The regional registry accounts for the SageMaker built-in XGBoost algorithm image. A built-in
# algorithm is the only way to run a REAL training job without building and pushing a container,
# and the image is AWS-owned, so no ECR repository has to be minted in the account.
_XGBOOST_REGISTRY_ACCOUNTS = {
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


def _algo_image(ctx: Any) -> str:

    account = _XGBOOST_REGISTRY_ACCOUNTS.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no SageMaker built-in XGBoost registry account is mapped for region "
            f"{ctx.region!r} in this check -- add it to close the gap"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/xgboost:1"


def _create_bucket(ctx: Any, s3: Any, bucket: str, scenario: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]}
    )


def _delete_bucket(s3: Any, bucket: str) -> None:
    try:
        while True:
            resp = s3.list_objects_v2(Bucket=bucket)
            contents = resp.get("Contents", [])
            if not contents:
                break
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _training_csv(n_rows: int = 60) -> bytes:
    """label,f1,f2 rows with label == 2*f1 + 3*f2 exactly."""
    lines = []
    for i in range(n_rows):
        f1 = (i % 10) + 0.5
        f2 = ((i * 3) % 10) + 0.5
        lines.append(f"{2.0 * f1 + 3.0 * f2:.4f},{f1:.4f},{f2:.4f}")
    return "\n".join(lines).encode("utf-8")


def _create_execution_role(ctx: Any, iam: Any, role_name: str, bucket: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "training-artifact"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="bucket-scoped",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }]}),
    )
    # IAM propagation exposes no condition to poll, so there is nothing to wait on here:
    # the bounded retry in _create_training_job_with_retry is what absorbs the delay.
    return arn


def _delete_role(iam: Any, role_name: str) -> None:
    for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    iam.delete_role(RoleName=role_name)


def _create_training_job_with_retry(sm: Any, *, timeout_s: float = 90.0, **kwargs) -> dict:
    """CreateTrainingJob, retrying only while the brand-new execution role is not yet assumable."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            msg = (err.get("Message") or "").lower()
            if err.get("Code") == "ValidationException" \
                    and ("assume role" in msg or "not authorized" in msg) \
                    and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _wait_training_terminal(sm: Any, job_name: str, *, timeout_s: float,
                            interval_s: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        if desc["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(
        f"training job {job_name} never reached a terminal state within {timeout_s}s: "
        f"status={desc.get('TrainingJobStatus')!r} secondary={desc.get('SecondaryStatus')!r}"
    )


def _stop_training_if_running(sm: Any, job_name: str) -> None:
    """A training job cannot be DELETED -- there is no DeleteTrainingJob. A Completed job is a
    permanent, non-billing metadata record; the only teardown that exists is stopping one that is
    still running, which is what this undoes."""
    desc = sm.describe_training_job(TrainingJobName=job_name)
    if desc["TrainingJobStatus"] in ("InProgress", "Stopping"):
        sm.stop_training_job(TrainingJobName=job_name)


def _list_all_keys(s3: Any, bucket: str, prefix: str) -> list:
    keys, token = [], None
    while True:
        kw = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kw["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kw)
        keys.extend(o["Key"] for o in resp.get("Contents", []))
        token = resp.get("NextContinuationToken")
        if not token:
            return sorted(keys)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A completed training job's S3ModelArtifacts names a real gzipped tar that decompresses, the only
    object under the job's output prefix, with ordered status transitions and bounded billable time.
    """
    image_uri = _algo_image(ctx)
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")
    # One bound on every target: the job's own MaxRuntimeInSeconds.
    timeout_s = 900

    bucket = ctx.unique_name("sim2real-sm-art-")
    _create_bucket(ctx, s3, bucket, "training-artifact")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_training_csv())

    role_arn = _create_execution_role(
        ctx, iam, ctx.unique_name("sim2real-sm-art-role-"), bucket
    )

    job_name = ctx.unique_name("sim2real-sm-art-job-")
    _create_training_job_with_retry(
        sm,
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        InputDataConfig=[{
            "ChannelName": "train",
            "ContentType": "text/csv",
            "DataSource": {"S3DataSource": {
                "S3DataType": "S3Prefix",
                "S3Uri": f"s3://{bucket}/train/",
                "S3DataDistributionType": "FullyReplicated",
            }},
        }],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={"objective": "reg:linear", "num_round": "15"},
        Tags=[{"Key": "sim2real", "Value": "training-artifact"}],
    )
    ctx.on_cleanup(lambda: _stop_training_if_running(sm, job_name))

    train_desc = _wait_training_terminal(sm, job_name, timeout_s=timeout_s)
    assert train_desc["TrainingJobStatus"] == "Completed", (
        f"the training job did not complete, so there is no artifact to interrogate: "
        f"status={train_desc['TrainingJobStatus']!r} "
        f"reason={train_desc.get('FailureReason')!r}"
    )

    # The URI is parsed structurally, never by splitting on '/'.
    uri = train_desc["ModelArtifacts"]["S3ModelArtifacts"]
    parsed = urlparse(uri)
    assert parsed.scheme == "s3" and parsed.netloc == bucket, (
        f"the reported artifact URI does not address the bucket this job was told to write to: "
        f"{uri!r}"
    )
    key = parsed.path.lstrip("/")
    assert key.startswith(f"output/{job_name}/"), (
        f"the reported artifact key is outside this job's OutputDataConfig prefix "
        f"output/{job_name}/: {key!r}"
    )

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] > 0, (
        f"the reported model artifact is a zero-byte object at {uri!r}: {head!r}"
    )

    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert len(body) == head["ContentLength"], (
        f"the artifact's bytes ({len(body)}) disagree with its ContentLength "
        f"({head['ContentLength']})"
    )
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
        members = archive.getmembers()
        files = [m for m in members if m.isfile()]
        extracted = {}
        for member in files:
            handle = archive.extractfile(member)
            assert handle is not None, f"archive member {member.name!r} is not readable"
            extracted[member.name] = handle.read()

    assert files, (
        f"the model archive opens but contains no file member: "
        f"{[(m.name, m.type) for m in members]!r}"
    )
    assert all(m.size > 0 for m in files), (
        f"the model archive contains an empty file member: "
        f"{[(m.name, m.size) for m in files]!r}"
    )
    assert all(len(data) == member.size
               for member, data in ((m, extracted[m.name]) for m in files)), (
        f"a member's extracted bytes disagree with its declared size: "
        f"{[(m.name, m.size, len(extracted[m.name])) for m in files]!r}"
    )
    uncompressed = sum(len(d) for d in extracted.values())
    assert uncompressed > len(body), (
        f"the artifact does not actually decompress -- {uncompressed} uncompressed bytes from a "
        f"{len(body)}-byte archive, so it is not a real gzipped model archive: "
        f"{[(m.name, m.size) for m in files]!r}"
    )

    # Effect present, and bounded: exactly one object under the job's output prefix.
    produced = _list_all_keys(s3, bucket, f"output/{job_name}/")
    assert produced == [key], (
        f"the job's output prefix must hold exactly the artifact it reported: {produced!r}, "
        f"expected [{key!r}]"
    )

    transitions = train_desc["SecondaryStatusTransitions"]
    statuses = [t["Status"] for t in transitions]
    assert statuses[-1] == "Completed", (
        f"the last secondary transition of a Completed job must be Completed: {statuses!r}"
    )
    # A subset, not equality: real jobs also pass through phases such as Downloading.
    assert {"Starting", "Training", "Uploading"} <= set(statuses), (
        f"a real training job must pass through Starting, Training and Uploading: {statuses!r}"
    )
    assert all(a["StartTime"] <= b["StartTime"] for a, b in zip(transitions, transitions[1:])), (
        f"secondary status transitions are not in chronological order: "
        f"{[(t['Status'], t['StartTime']) for t in transitions]!r}"
    )
    assert all(t.get("StatusMessage") for t in transitions), (
        f"every secondary transition of a real job carries a StatusMessage: {transitions!r}"
    )

    # Billable time covers the billed phases (rounded up), not the job's whole lifetime.
    billable = train_desc["BillableTimeInSeconds"]
    trained_for = (
        train_desc["TrainingEndTime"] - train_desc["TrainingStartTime"]
    ).total_seconds()
    assert billable > 0, f"a job that ran must report billable time: {billable!r}"
    assert billable <= int(trained_for) + 60, (
        f"BillableTimeInSeconds ({billable}) exceeds the wall clock between TrainingStartTime and "
        f"TrainingEndTime ({trained_for:.1f}s) by more than the rounding margin: "
        f"{train_desc['TrainingStartTime']!r} .. {train_desc['TrainingEndTime']!r}"
    )
    assert train_desc["CreationTime"] <= train_desc["TrainingStartTime"] \
        <= train_desc["TrainingEndTime"] <= train_desc["LastModifiedTime"], (
        f"the job's four timestamps are not ordered: creation="
        f"{train_desc['CreationTime']!r} start={train_desc['TrainingStartTime']!r} "
        f"end={train_desc['TrainingEndTime']!r} modified={train_desc['LastModifiedTime']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
