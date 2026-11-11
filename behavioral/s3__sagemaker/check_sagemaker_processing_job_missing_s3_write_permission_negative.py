"""sagemaker-processing-job-missing-s3-write-permission-negative."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-processing-job-missing-s3-write-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A processing job whose role can read the input but lacks s3:PutObject on the output ends Failed with
    an access-denied FailureReason and writes no output, while the same job with the grant completes and
    writes processing-output-good/data.csv."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    role_good = _create_sagemaker_role(
        ctx,
        statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/processing-input/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/code/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/processing-output-good/*"],
            },
        ],
    )
    # role_bad can read the input fine, but can only write to an unrelated scratch
    # prefix -- not the configured output prefix, which is the one broken permission.
    role_bad = _create_sagemaker_role(
        ctx,
        statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/processing-input/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/code/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/scratch-unrelated/*"],
            },
        ],
    )

    rows = [["a", "1"], ["b", "2"]]
    s3.put_object(
        Bucket=bucket,
        Key="processing-input/data.csv",
        Body=_rows_to_csv(rows).encode("utf-8"),
    )

    # positive control: a role that CAN write to the configured output -> succeeds.
    _, desc_good = _run_processing_job(
        ctx,
        role_arn=role_good,
        bucket=bucket,
        input_s3_uri=f"s3://{bucket}/processing-input/data.csv",
        output_s3_uri=f"s3://{bucket}/processing-output-good/",
        job_prefix="proc-good",
    )
    assert desc_good["ProcessingJobStatus"] == "Completed", desc_good.get(
        "FailureReason"
    )
    good_keys = _list_keys(ctx, bucket, "processing-output-good/data.csv")
    assert good_keys == ["processing-output-good/data.csv"], (
        f"expected the good role's output to be persisted, got {good_keys!r}"
    )

    # negative: identical input, only the role's write permission on the configured
    # output prefix is missing.
    _, desc_bad = _run_processing_job(
        ctx,
        role_arn=role_bad,
        bucket=bucket,
        input_s3_uri=f"s3://{bucket}/processing-input/data.csv",
        output_s3_uri=f"s3://{bucket}/processing-output-bad/",
        job_prefix="proc-bad",
    )
    assert desc_bad["ProcessingJobStatus"] == "Failed", (
        f"expected the processing job to fail without write access to its output, got {desc_bad['ProcessingJobStatus']}"
    )
    reason = desc_bad.get("FailureReason") or ""
    assert "AccessDenied" in reason or "Forbidden" in reason or "403" in reason, (
        f"unexpected failure reason: {reason!r}"
    )
    assert _list_keys(ctx, bucket, "processing-output-bad/") == [], (
        "no output should have been persisted"
    )


SKLEARN_ACCOUNT_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "141502667606",
}
SKLEARN_IMAGE_TAG = "1.2-1-cpu-py3"

PROCESSING_SCRIPT = (
    "import csv, glob, os\n"
    "in_dir = '/opt/ml/processing/input/data'\n"
    "out_dir = '/opt/ml/processing/output/results'\n"
    "os.makedirs(out_dir, exist_ok=True)\n"
    "for path in sorted(glob.glob(os.path.join(in_dir, '*.csv'))):\n"
    "    with open(path, newline='') as fh:\n"
    "        rows = list(csv.reader(fh))\n"
    "    out_rows = [r + ['PROCESSED'] for r in rows]\n"
    "    with open(os.path.join(out_dir, os.path.basename(path)), 'w', newline='') as fh:\n"
    "        csv.writer(fh).writerows(out_rows)\n"
)


def _rows_to_csv(rows) -> str:
    return "\n".join(",".join(r) for r in rows) + "\n"


def _sklearn_image_uri(region: str) -> str:
    account = SKLEARN_ACCOUNT_BY_REGION.get(region)
    if not account:
        raise AssertionError(
            f"no known sagemaker-scikit-learn ECR account mapped for region {region}; "
            "extend SKLEARN_ACCOUNT_BY_REGION to enable this check there"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-scikit-learn:{SKLEARN_IMAGE_TAG}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-s3-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={
            "TagSet": [{"Key": "sim2real", "Value": "missing-s3-write-permission"}]
        },
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _list_keys(ctx, bucket, prefix):
    resp = ctx.client("s3").list_objects_v2(Bucket=bucket, Prefix=prefix)
    return [o["Key"] for o in resp.get("Contents", [])]


def _create_sagemaker_role(ctx, *, statements) -> str:
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
        AssumeRolePolicyDocument=_json_dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "missing-s3-write-permission"}],
    )["Role"]["Arn"]
    policy_name = ctx.unique_name("sim2real-sm-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=_json_dumps({"Version": "2012-10-17", "Statement": statements}),
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


def _poll_until(
    probe, predicate, *, timeout_s: float = 900.0, interval_s: float = 20.0
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"condition not reached within {timeout_s}s; last observed={last!r}"
    )


def _wait_for_terminal(
    describe_fn, status_key, *, timeout_s: float = 900.0, interval_s: float = 20.0
):
    terminal = {"Completed", "Failed", "Stopped"}
    return _poll_until(
        describe_fn,
        lambda resp: resp[status_key] in terminal,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _run_processing_job(
    ctx, *, role_arn, bucket, input_s3_uri, output_s3_uri, job_prefix="proc"
):
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    job_name = ctx.unique_name(f"sim2real-sm-{job_prefix}-")
    image = _sklearn_image_uri(ctx.region)
    code_key = "code/script.py"
    s3.put_object(Bucket=bucket, Key=code_key, Body=PROCESSING_SCRIPT.encode("utf-8"))

    def _create():
        return sm.create_processing_job(
            ProcessingJobName=job_name,
            RoleArn=role_arn,
            AppSpecification={
                "ImageUri": image,
                "ContainerEntrypoint": [
                    "python3",
                    "/opt/ml/processing/input/code/script.py",
                ],
            },
            ProcessingInputs=[
                {
                    "InputName": "data",
                    "S3Input": {
                        "S3Uri": input_s3_uri,
                        "LocalPath": "/opt/ml/processing/input/data",
                        "S3DataType": "S3Prefix",
                        "S3InputMode": "File",
                        "S3DataDistributionType": "FullyReplicated",
                    },
                },
                {
                    "InputName": "code",
                    "S3Input": {
                        "S3Uri": f"s3://{bucket}/{code_key}",
                        "LocalPath": "/opt/ml/processing/input/code",
                        "S3DataType": "S3Prefix",
                        "S3InputMode": "File",
                        "S3DataDistributionType": "FullyReplicated",
                    },
                },
            ],
            ProcessingOutputConfig={
                "Outputs": [
                    {
                        "OutputName": "results",
                        "S3Output": {
                            "S3Uri": output_s3_uri,
                            "LocalPath": "/opt/ml/processing/output/results",
                            "S3UploadMode": "EndOfJob",
                        },
                    }
                ]
            },
            ProcessingResources={
                "ClusterConfig": {
                    "InstanceType": "ml.m5.large",
                    "InstanceCount": 1,
                    "VolumeSizeInGB": 5,
                }
            },
            StoppingCondition={"MaxRuntimeInSeconds": 1200},
        )

    _retry_role_not_ready(_create)
    desc = _wait_for_terminal(
        lambda: sm.describe_processing_job(ProcessingJobName=job_name),
        "ProcessingJobStatus",
    )
    return job_name, desc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
