"""model-invocation-job-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-invocation-job-timestamp-precision-preserved"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A batch inference job's sub-second submitTime is returned identically (not truncated or
    regenerated) across repeated GetModelInvocationJob reads over a few seconds."""
    bedrock = ctx.client("bedrock")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    bucket = ctx.unique_name("sim2real-behav-mij-").replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    # 100 records is the batch inference minimum; the job is stopped in cleanup.
    lines = [
        json.dumps(
            {
                "recordId": f"REC{i:05d}",
                "modelInput": {"prompt": "hi", "max_gen_len": 8},
            }
        )
        for i in range(100)
    ]
    s3.put_object(Bucket=bucket, Key="input.jsonl", Body=("\n".join(lines)).encode("utf-8"))

    role_arn = _create_batch_role(ctx, iam, sts, bucket)

    job_name = ctx.unique_name("sim2real-behav-mij-")
    job_arn = _retry_create_job(
        bedrock,
        job_name=job_name,
        role_arn=role_arn,
        bucket=bucket,
        region=ctx.region,
    )
    ctx.on_cleanup(lambda: _ignore_conflict(lambda: bedrock.stop_model_invocation_job(jobIdentifier=job_arn)))

    first = bedrock.get_model_invocation_job(jobIdentifier=job_arn)["submitTime"]

    # Re-read across a real elapsed window so a submitTime regenerated only later is caught.
    reads = [first]
    deadline = time.monotonic() + 6.0
    while time.monotonic() < deadline:
        time.sleep(1.5)
        reads.append(bedrock.get_model_invocation_job(jobIdentifier=job_arn)["submitTime"])

    assert len(reads) >= 4, f"expected at least 4 reads across the window, got {len(reads)}"
    for i, later in enumerate(reads[1:], start=1):
        assert later == first, f"submitTime drifted on read {i}: first={first!r} later={later!r}"


def _retry_create_job(bedrock, *, job_name, role_arn, bucket, region, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = bedrock.create_model_invocation_job(
                jobName=job_name,
                roleArn=role_arn,
                modelId=f"arn:aws:bedrock:{region}::foundation-model/meta.llama3-1-8b-instruct-v1:0",
                inputDataConfig={"s3InputDataConfig": {"s3Uri": f"s3://{bucket}/input.jsonl"}},
                outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/output/"}},
                tags=[{"key": "sim2real", "value": "audit"}],
            )
            return resp["jobArn"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = err
                time.sleep(4)
                continue
            raise
    raise AssertionError(f"CreateModelInvocationJob never succeeded (IAM propagation?): {last_err}")


def _create_bucket(ctx, s3, bucket):
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "audit"}]}
    )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))


def _delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_batch_role(ctx, iam, sts, bucket):
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-mijrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
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
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(access_policy)
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_role(iam, role_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _ignore_conflict(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ConflictException", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
