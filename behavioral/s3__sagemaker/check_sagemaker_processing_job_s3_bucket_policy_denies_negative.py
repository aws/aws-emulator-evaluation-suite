"""sagemaker-processing-job-s3-bucket-policy-denies-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-processing-job-s3-bucket-policy-denies-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A processing job whose execution role has full IAM S3 permissions still fails
    to read its input once an explicit bucket-policy Deny targets that role's ARN —
    IAM allow never overrides an explicit resource-policy deny."""
    image_uri = _resolve_sklearn_processing_image(ctx)
    bucket = _create_bucket(ctx)
    # Two distinct roles (both IAM-allowed) so the OK and DENY jobs can run concurrently:
    # the bucket policy below denies only role_deny's ARN, never role_ok's.
    role_ok = _create_execution_role(ctx, bucket)
    role_deny = _create_execution_role(ctx, bucket)
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    s3.put_object(Bucket=bucket, Key="input/data.txt", Body=b"ok-input")

    script = (
        "import pathlib\n"
        "src = pathlib.Path('/opt/ml/processing/input')\n"
        "dst = pathlib.Path('/opt/ml/processing/output')\n"
        "dst.mkdir(parents=True, exist_ok=True)\n"
        "for f in sorted(src.iterdir()):\n"
        "    (dst / (f.name + '.out')).write_text(f.read_text().upper())\n"
    )
    inputs = [
        {
            "InputName": "input-1",
            "S3Input": {
                "S3Uri": f"s3://{bucket}/input/",
                "LocalPath": "/opt/ml/processing/input",
                "S3DataType": "S3Prefix",
                "S3InputMode": "File",
                "S3DataDistributionType": "FullyReplicated",
            },
        }
    ]

    # Break exactly one thing up front: an explicit Deny on s3:GetObject for role_deny's
    # ARN only. role_ok is untouched, so both jobs can be launched back-to-back and run
    # concurrently instead of sequentially (halving real-AWS wall-clock time).
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyExecutionRoleGet",
                "Effect": "Deny",
                "Principal": {"AWS": role_deny},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/input/*",
            }
        ],
    }
    _put_bucket_policy_with_retry(s3, bucket, deny_policy)
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=bucket))
    _wait_for_bucket_policy(s3, bucket, "DenyExecutionRoleGet")

    outputs_ok = [
        {
            "OutputName": "output-1",
            "S3Output": {
                "S3Uri": f"s3://{bucket}/output-ok/",
                "LocalPath": "/opt/ml/processing/output",
                "S3UploadMode": "EndOfJob",
            },
        }
    ]
    outputs_deny = [
        {
            "OutputName": "output-1",
            "S3Output": {
                "S3Uri": f"s3://{bucket}/output-deny/",
                "LocalPath": "/opt/ml/processing/output",
                "S3UploadMode": "EndOfJob",
            },
        }
    ]

    job_ok = _run_processing_job(
        ctx, sm, s3, bucket, role_arn=role_ok, image_uri=image_uri, script=script, inputs=inputs, outputs=outputs_ok
    )
    job_deny = _run_processing_job(
        ctx,
        sm,
        s3,
        bucket,
        role_arn=role_deny,
        image_uri=image_uri,
        script=script,
        inputs=inputs,
        outputs=outputs_deny,
    )

    final_ok, final_deny = _wait_processing_jobs(sm, job_ok, job_deny)

    assert final_ok["ProcessingJobStatus"] == "Completed", final_ok.get("FailureReason")
    assert s3.get_object(Bucket=bucket, Key="output-ok/data.txt.out")["Body"].read().decode() == "OK-INPUT"

    assert final_deny["ProcessingJobStatus"] == "Failed"
    reason = final_deny.get("FailureReason", "").lower()
    assert "access" in reason or "denied" in reason or "forbidden" in reason, reason
    assert not s3.list_objects_v2(Bucket=bucket, Prefix="output-deny/").get("Contents")


# ===== helpers =====


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "RepositoryNotFoundException") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        objs = [{"Key": o["Key"]} for o in s3.list_objects_v2(Bucket=name).get("Contents", [])]
        for i in range(0, len(objs), 1000):
            batch = objs[i : i + 1000]
            if batch:
                s3.delete_objects(Bucket=name, Delete={"Objects": batch})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_execution_role(ctx, bucket, *, allow_get=True, allow_put=True, kms_key_arn=None):
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    s3_actions = ["s3:ListBucket"]
    if allow_get:
        s3_actions.append("s3:GetObject")
    if allow_put:
        s3_actions.append("s3:PutObject")
    statements = [
        {
            "Effect": "Allow",
            "Action": s3_actions,
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            "Resource": "arn:aws:logs:*:*:*",
        },
    ]
    if kms_key_arn:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
                "Resource": kms_key_arn,
            }
        )
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _retry_role_propagation(fn, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last}")


def _put_bucket_policy_with_retry(s3, bucket, policy, *, timeout_s=120.0, interval_s=5.0):
    """A bucket policy whose Principal names an IAM role created moments ago can be rejected
    with MalformedPolicy ("Invalid principal in policy") until that role has propagated
    through IAM; retry the PutBucketPolicy call itself, since that is the exact call being
    validated against the new principal, not the role creation that preceded it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "").lower()
            if code == "MalformedPolicy" and "principal" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _wait_for_bucket_policy(s3, bucket, expected_sid, *, timeout_s=30.0, interval_s=2.0):
    return _poll_until(
        lambda: s3.get_bucket_policy(Bucket=bucket)["Policy"],
        lambda p: expected_sid in p,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


_FRAMEWORK_ECR_ACCOUNT_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ca-central-1": "341280168497",
    "sa-east-1": "737474898029",
}


def _resolve_sklearn_processing_image(ctx):
    # AWS-owned "sagemaker-scikit-learn" framework container registry paths are
    # publicly documented (see AWS docs "Accessing Docker Images for Scikit-learn and
    # Spark ML") — hardcoded here since the 'sagemaker' Python SDK isn't installed.
    account = _FRAMEWORK_ECR_ACCOUNT_BY_REGION.get(ctx.region)
    if not account:
        raise AssertionError(f"no known AWS-owned scikit-learn container account ID for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"


def _run_processing_job(ctx, sm, s3, bucket, *, role_arn, image_uri, script, inputs, outputs, kms_key_id=None):
    name = ctx.unique_name("sim2real-sm-proc-")
    output_config = {"Outputs": outputs}
    if kms_key_id:
        output_config["KmsKeyId"] = kms_key_id

    # CreateProcessingJob's ContainerEntrypoint elements are capped at 256 chars each — far
    # too short to inline a real script. Stage it in S3 instead and have a short bootstrap
    # one-liner fetch + exec it (the execution role already has s3:GetObject on this bucket).
    script_key = f"_bootstrap/{name}.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=script.encode())
    bootstrap = (
        f"import boto3;boto3.client('s3').download_file('{bucket}','{script_key}','/tmp/s.py');"
        "exec(open('/tmp/s.py').read())"
    )
    assert len(bootstrap) <= 256, f"bootstrap one-liner too long ({len(bootstrap)} chars)"

    def _create():
        sm.create_processing_job(
            ProcessingJobName=name,
            RoleArn=role_arn,
            AppSpecification={"ImageUri": image_uri, "ContainerEntrypoint": ["python3", "-c", bootstrap]},
            ProcessingInputs=inputs,
            ProcessingOutputConfig=output_config,
            ProcessingResources={
                "ClusterConfig": {"InstanceCount": 1, "InstanceType": "ml.m5.large", "VolumeSizeInGB": 5}
            },
            StoppingCondition={"MaxRuntimeInSeconds": 900},
        )

    _retry_role_propagation(_create)
    ctx.on_cleanup(lambda: _stop_processing_job(sm, name))
    return name


def _stop_processing_job(sm, name):
    try:
        status = sm.describe_processing_job(ProcessingJobName=name)["ProcessingJobStatus"]
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    if status == "InProgress":
        try:
            sm.stop_processing_job(ProcessingJobName=name)
        except ClientError as exc:
            if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_processing_job(ProcessingJobName=name)["ProcessingJobStatus"] == "InProgress"):
                raise


def _wait_processing_jobs(sm, *names, timeout_s=900.0, interval_s=8.0):
    """Poll multiple processing jobs concurrently, returning each final describe() in order."""
    terminal = ("Completed", "Failed", "Stopped")
    deadline = time.monotonic() + timeout_s
    finals = {}
    while time.monotonic() < deadline and len(finals) < len(names):
        for n in names:
            if n in finals:
                continue
            desc = sm.describe_processing_job(ProcessingJobName=n)
            if desc["ProcessingJobStatus"] in terminal:
                finals[n] = desc
        if len(finals) < len(names):
            time.sleep(interval_s)
    for n in names:
        if n not in finals:
            raise AssertionError(f"processing job {n} did not reach a terminal state within {timeout_s}s")
    return tuple(finals[n] for n in names)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
