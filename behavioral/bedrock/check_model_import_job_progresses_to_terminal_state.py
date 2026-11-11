"""model-import-job-progresses-to-terminal-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "model-import-job-progresses-to-terminal-state"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModelImportJob starts InProgress and GetModelImportJob eventually reports
    a terminal Completed/Failed status."""
    bedrock = ctx.client("bedrock")
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="import/config.json", Body=b'{"fake": "artifact"}')
    role_arn = _create_bedrock_role(ctx, bucket)

    job_name = ctx.unique_name("sim2real-importjob-")
    imported_model_name = ctx.unique_name("sim2real-importedmodel-")

    create_resp = _retry_transient(
        lambda: bedrock.create_model_import_job(
            jobName=job_name,
            importedModelName=imported_model_name,
            roleArn=role_arn,
            modelDataSource={"s3DataSource": {"s3Uri": f"s3://{bucket}/import/"}},
            jobTags=[{"key": "sim2real-check", "value": CHECK}],
            importedModelTags=[{"key": "sim2real-check", "value": CHECK}],
        )
    )
    job_arn = create_resp["jobArn"]

    got = bedrock.get_model_import_job(jobIdentifier=job_arn)
    assert got["jobName"] == job_name, f"jobName: expected {job_name!r}, got {got['jobName']!r}"
    assert got["roleArn"] == role_arn, f"roleArn: expected {role_arn!r}, got {got['roleArn']!r}"
    assert got["importedModelName"] == imported_model_name, (
        f"importedModelName: expected {imported_model_name!r}, got {got['importedModelName']!r}"
    )

    final = _poll_until(
        lambda: bedrock.get_model_import_job(jobIdentifier=job_arn),
        lambda r: r["status"] in ("Completed", "Failed"),
        timeout_s=900.0,
        interval_s=20.0,
    )
    if final["status"] == "Failed":
        assert final.get("failureMessage"), (
            f"job {job_arn} terminated Failed with no failureMessage: {final!r}"
        )
    else:
        assert final.get("importedModelArn"), (
            f"job {job_arn} terminated Completed with no importedModelArn: {final!r}"
        )
        imported = bedrock.get_imported_model(modelIdentifier=final["importedModelArn"])
        assert imported["modelArn"] == final["importedModelArn"], (
            f"get_imported_model modelArn mismatch: expected {final['importedModelArn']!r}, "
            f"got {imported['modelArn']!r}"
        )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-").lower().replace("_", "-")
    region = ctx.region
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_bedrock_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy)
    )

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_transient(fn, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
