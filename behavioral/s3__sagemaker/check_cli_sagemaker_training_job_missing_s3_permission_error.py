"""cli-sagemaker-training-job-missing-s3-permission-error."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sagemaker-training-job-missing-s3-permission-error"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI create-training-job with a role that has no S3 permission is refused at once with the exact
    ValidationException naming the denied s3:ListBucket, so no job or artifact exists, while the same
    job with an S3-capable role completes and writes its artifact."""
    require_tools("aws")

    region = ctx.region
    image_uri = _training_image_uri(region)

    bucket = _create_bucket(ctx)
    _upload_csv_via_cli(ctx, bucket, "input/data.csv")

    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")

    # --- broken: role has no S3 permission at all (only CloudWatch Logs, to isolate the
    # failure to the S3 data channel rather than an unrelated logging permission gap) ---
    no_s3_role_arn, _ = _create_sagemaker_role(ctx, allow_s3=False)
    broken_job_name = ctx.unique_name("sim2real-sm-trn-nos3-")
    broken_stderr = _run_aws_create_expect_s3_denied(
        ctx,
        "sagemaker",
        "create-training-job",
        _training_payload(broken_job_name, no_s3_role_arn, image_uri, bucket, "output-broken/"),
    )
    expected_message = _no_s3_objects_message(
        ctx, f"s3://{bucket}/input/", bucket, no_s3_role_arn, list_denied=True
    )
    assert broken_stderr.strip() == (
        "aws: [ERROR]: An error occurred (ValidationException) when calling the CreateTrainingJob "
        "operation: "
        f"{expected_message}"
    ), f"expected the exact missing-S3-permission rejection, got: {broken_stderr[-1000:]}"
    try:
        sm.describe_training_job(TrainingJobName=broken_job_name)
        raise AssertionError(
            f"describe-training-job found {broken_job_name!r}, but create-training-job was "
            f"rejected -- the job must never have been created"
        )
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ValidationException", (
            f"expected ValidationException (no such job), got: {e.response['Error']}"
        )
        assert e.response["Error"]["Message"] == "Requested resource not found.", e.response["Error"]
    broken_listing = s3.list_objects_v2(Bucket=bucket, Prefix="output-broken/")
    assert "Contents" not in broken_listing, (
        f"a rejected job must not have written any output artifact, found "
        f"{[o['Key'] for o in broken_listing.get('Contents', [])]}"
    )

    # --- positive control: identical job, role WITH S3 permission, must complete and produce
    # its output artifact — proves the failure above is specifically the missing permission,
    # not something else about the fixture (image, input data, instance type, ...) ---
    ok_role_arn, _ = _create_sagemaker_role(ctx, allow_s3=True)
    ok_job_name = ctx.unique_name("sim2real-sm-trn-oks3-")
    _run_aws_create_with_role_retry(
        ctx,
        "sagemaker",
        "create-training-job",
        _training_payload(ok_job_name, ok_role_arn, image_uri, bucket, "output-ok/"),
    )
    ok_job = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=ok_job_name),
        lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    assert ok_job["TrainingJobStatus"] == "Completed", (
        f"positive control training job did not complete: status={ok_job['TrainingJobStatus']} "
        f"reason={ok_job.get('FailureReason')}"
    )
    ok_listing = s3.list_objects_v2(Bucket=bucket, Prefix="output-ok/")
    assert ok_listing.get("Contents"), "positive control job must have written an output artifact"
    model_s3_uri = ok_job["ModelArtifacts"]["S3ModelArtifacts"]
    artifact_text = _read_tar_member_from_s3(ctx, model_s3_uri, "artifact.txt")
    assert _TRAIN_ARTIFACT_MARKER in artifact_text, (
        f"expected the container's own marker in the uploaded model artifact, got: {artifact_text!r}"
    )


_TRAIN_ARTIFACT_MARKER = "sim2real-training-artifact-ok"


def _training_payload(job_name, role_arn, image_uri, bucket, output_prefix):
    return {
        "TrainingJobName": job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": image_uri,
            "ContainerEntrypoint": ["/bin/sh", "-c"],
            "ContainerArguments": [
                f"mkdir -p /opt/ml/model && echo {_TRAIN_ARTIFACT_MARKER} > /opt/ml/model/artifact.txt"
            ],
        },
        "InputDataConfig": [
            {
                "ChannelName": "training",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/input/",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/{output_prefix}"},
        "ResourceConfig": {
            "InstanceType": "ml.m5.large",
            "InstanceCount": 1,
            "VolumeSizeInGB": 1,
        },
        "StoppingCondition": {"MaxRuntimeInSeconds": 1800},
    }


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with leased AWS creds + region in the
    env (via ctx.subprocess_env). Raises on non-zero exit when check=True. Returns CompletedProcess."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    """Run a multi-line bash script (set -euo pipefail) with leased AWS creds configured."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(
            ctx,
            ["bash", script_path],
            timeout_s=timeout_s,
            check=check,
            env_extra=env_extra,
        )
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    """Run an AWS CLI command; return parsed JSON (dict/list) or raw stdout string."""
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", "--no-cli-pager", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


_DLC_ACCOUNT = "763104351884"
_UNSUPPORTED_REGION_PREFIXES = ("cn-", "us-gov-", "us-iso")


def _training_image_uri(region: str) -> str:
    if region.startswith(_UNSUPPORTED_REGION_PREFIXES):
        raise AssertionError(
            f"no known Deep Learning Container registry account mapping for region {region}"
        )
    return f"{_DLC_ACCOUNT}.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-bkt-")
    # us-east-1 doesn't take LocationConstraint; other regions require it
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "sm-training-job-missing-s3-permission"}]},
    )

    def _cleanup():
        while True:
            resp = s3.list_objects_v2(Bucket=name)
            contents = resp.get("Contents", [])
            if not contents:
                break
            s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            )
            if not resp.get("IsTruncated"):
                break
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _upload_csv_via_cli(ctx, bucket: str, key: str) -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("feature1,feature2,label\n1,2,0\n3,4,1\n")
        local_path = f.name
    try:
        _run_aws(ctx, "s3", "cp", local_path, f"s3://{bucket}/{key}")
    finally:
        os.unlink(local_path)


def _create_sagemaker_role(ctx, allow_s3: bool = True):
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "sm-training-job-missing-s3-permission"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    log_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="logs-access", PolicyDocument=json.dumps(log_policy)
    )
    if allow_s3:
        s3_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                    "Resource": "*",
                }
            ],
        }
        iam.put_role_policy(
            RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(s3_policy)
        )
    return role_arn, role_name


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    iam.delete_role(RoleName=role_name)


def _run_aws_create_with_role_retry(
    ctx, service: str, operation: str, payload: dict, timeout_s: float = 150.0, interval_s: float = 10.0
):
    """Run an `aws <service> <operation> --cli-input-json ...` call, retrying while the failure
    looks like IAM role propagation lag (the just-created role not yet assumable/passable)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        path = f.name
    try:
        deadline = time.monotonic() + timeout_s
        last_stderr = ""
        while time.monotonic() < deadline:
            proc = _run_shell(
                ctx,
                [
                    "aws",
                    "--output",
                    "json",
                    "--no-cli-pager",
                    service,
                    operation,
                    "--cli-input-json",
                    f"file://{path}",
                ],
                timeout_s=30.0,
                check=False,
            )
            if proc.returncode == 0:
                return json.loads(proc.stdout) if proc.stdout.strip() else {}
            last_stderr = proc.stderr
            if (
                "is not authorized" in proc.stderr
                or "AccessDenied" in proc.stderr
                or "ValidationException" in proc.stderr
            ):
                time.sleep(interval_s)
                continue
            raise AssertionError(f"{service} {operation} failed: {proc.stderr[-500:]}")
        raise AssertionError(
            f"{service} {operation} did not succeed after role-propagation retries: "
            f"{last_stderr[-500:]}"
        )
    finally:
        os.unlink(path)


def _run_aws_create_expect_s3_denied(
    ctx, service: str, operation: str, payload: dict, timeout_s: float = 60.0, interval_s: float = 5.0
) -> str:
    """Submit once, retrying only while the failure looks like IAM trust/PassRole propagation lag
    on the call itself (the just-created role not yet assumable) -- NEVER while it names an S3
    permission, since that is the permanent rejection this helper exists to observe. Returns the
    rejecting stderr; raises if the call unexpectedly succeeds."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        path = f.name
    try:
        deadline = time.monotonic() + timeout_s
        while True:
            proc = _run_shell(
                ctx,
                [
                    "aws",
                    "--output",
                    "json",
                    "--no-cli-pager",
                    service,
                    operation,
                    "--cli-input-json",
                    f"file://{path}",
                ],
                timeout_s=30.0,
                check=False,
            )
            if proc.returncode == 0:
                raise AssertionError(
                    f"expected {service} {operation} to be rejected for missing S3 permission, "
                    f"but it succeeded: {proc.stdout[:300]}"
                )
            stderr = proc.stderr
            trust_propagation_lag = (
                "s3:" not in stderr
                and ("sts:AssumeRole" in stderr or "assume role" in stderr.lower())
            )
            if trust_propagation_lag and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return stderr
    finally:
        os.unlink(path)


def _read_tar_member_from_s3(ctx, s3_uri: str, member_name: str) -> str:
    assert s3_uri.startswith("s3://"), s3_uri
    bucket, _, key = s3_uri[len("s3://"):].partition("/")
    s3 = ctx.client("s3")
    data = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        member = tar.extractfile(member_name)
        return member.read().decode("utf-8")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _no_s3_objects_message(ctx, s3_uri: str, bucket: str, role_arn: str, *, list_denied: bool) -> str:
    """SageMaker's exact refusal when an input channel's S3 prefix lists no objects for the role."""
    message = (
        f'No S3 objects found under S3 URL "{s3_uri}" given in input data source. Please ensure '
        f"that the bucket exists in the selected region ({ctx.region}), that objects exist under "
        f'that S3 prefix, and that the role "{role_arn}" has "s3:ListBucket" permissions on '
        f'bucket "{bucket}".'
    )
    if list_denied:
        role_name = role_arn.rsplit("/", 1)[-1]
        message += (
            f" Error message from S3: User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/"
            f'SageMaker is not authorized to perform: s3:ListBucket on resource: "arn:aws:s3:::'
            f'{bucket}" because no identity-based policy allows the s3:ListBucket action'
        )
    return message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
