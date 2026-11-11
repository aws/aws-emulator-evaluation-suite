"""sagemaker-processing-job-output-data-format-preserved."""
from __future__ import annotations

import csv
import io
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-processing-job-output-data-format-preserved"
GROUP = "data-format"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A completed processing job's output keeps every source row and field byte-for-byte and appends one
    PROCESSED column, so the first line reads 007,3.1400,alpha,PROCESSED (no reformatted numbers,
    stripped zeros or changed delimiter)."""
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

    # deliberately format-sensitive fields: a zero-padded int, a fixed-precision
    # float, and a plain string -- a lossy round trip (e.g. one that decodes/reencodes
    # through JSON or normalizes numerics) would corrupt at least one of these.
    rows = [
        ["007", "3.1400", "alpha"],
        ["042", "0.5000", "beta"],
        ["100", "10.2500", "gamma"],
    ]
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="processing-input/data.csv", Body=_rows_to_csv(rows).encode("utf-8"))

    _, desc = _run_processing_job(
        ctx,
        role_arn=role_arn,
        bucket=bucket,
        input_s3_uri=f"s3://{bucket}/processing-input/data.csv",
        output_s3_uri=f"s3://{bucket}/processing-output/",
    )
    assert desc["ProcessingJobStatus"] == "Completed", desc.get("FailureReason")

    body = s3.get_object(Bucket=bucket, Key="processing-output/data.csv")["Body"].read().decode("utf-8")
    out_rows = list(csv.reader(io.StringIO(body)))

    assert len(out_rows) == len(rows), f"row count not preserved: expected {len(rows)}, got {len(out_rows)}"
    for src_row, out_row in zip(rows, out_rows):
        assert len(out_row) == len(src_row) + 1, f"column count not preserved: {src_row!r} -> {out_row!r}"
        assert out_row[:-1] == src_row, f"field formatting corrupted: {src_row!r} -> {out_row[:-1]!r}"
        assert out_row[-1] == "PROCESSED", f"marker column missing or wrong: expected 'PROCESSED', got {out_row[-1]!r}"
    # the raw bytes must still be comma-delimited text, not re-serialized (e.g. JSON).
    first_line = body.strip().splitlines()[0]
    assert first_line == "007,3.1400,alpha,PROCESSED", f"expected '007,3.1400,alpha,PROCESSED', got {first_line!r}"


# AWS-owned ECR registry account for the prebuilt sagemaker-scikit-learn image; the account
# is genuinely region-pinned (a distinct ECR registry per region), not a resource this check owns.
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-owner", "Value": "behavioral-suite"}]})

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
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
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


def _run_processing_job(ctx, *, role_arn, bucket, input_s3_uri, output_s3_uri, job_prefix="proc"):
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    job_name = ctx.unique_name(f"sim2real-sm-{job_prefix}-")
    image = _sklearn_image_uri(ctx.region)
    code_key = f"code/{job_name}/script.py"
    s3.put_object(Bucket=bucket, Key=code_key, Body=PROCESSING_SCRIPT.encode("utf-8"))

    def _create():
        return sm.create_processing_job(
            ProcessingJobName=job_name,
            RoleArn=role_arn,
            AppSpecification={
                "ImageUri": image,
                "ContainerEntrypoint": ["python3", "/opt/ml/processing/input/code/script.py"],
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
            ProcessingResources={"ClusterConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5}},
            StoppingCondition={"MaxRuntimeInSeconds": 1200},
            Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
        )

    _retry_role_not_ready(_create)
    desc = _wait_for_terminal(lambda: sm.describe_processing_job(ProcessingJobName=job_name), "ProcessingJobStatus")
    return job_name, desc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
