"""get-pipeline-not-found."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-pipeline-not-found"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPipeline for a name that was never created raises PipelineNotFoundException,
    verified against a positive control (GetPipeline on a real pipeline succeeds) so the
    rejection cannot be confused with GetPipeline failing unconditionally."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _upload_source_zip(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-getnf-")
    pipeline_def = _two_stage_pipeline(name, role_arn, bucket, key)
    _wait_role_usable(lambda: cp.create_pipeline(pipeline=pipeline_def))
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    # Positive control: GetPipeline on a real, freshly created pipeline succeeds.
    assert cp.get_pipeline(name=name)["pipeline"]["name"] == name

    absent = ctx.unique_name("sim2real-cp-getnf-absent-")
    refusal = _error_code(lambda: cp.get_pipeline(name=absent))
    assert refusal == (
        "PipelineNotFoundException",
        f"Account '{ctx.account}' does not have a pipeline with name '{absent}'",
    ), refusal


def _error_code(fn) -> tuple[str, str]:
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup() -> None:
        resp = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_source_zip(ctx, bucket: str, key: str = "source.zip") -> str:
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real-behavioral-source")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return key


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codepipeline.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cp-policy-")
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:PutObject",
                        "s3:GetBucketVersioning",
                        "s3:ListBucket",
                    ],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _wait_role_usable(fn, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in (
                "InvalidStructureException",
                "InvalidParameterValueException",
                "InvalidRoleException",
            ) or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _two_stage_pipeline(name: str, role_arn: str, bucket: str, source_key: str) -> dict:
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "SourceAction",
                        "actionTypeId": {
                            "category": "Source",
                            "owner": "AWS",
                            "provider": "S3",
                            "version": "1",
                        },
                        "outputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": {
                            "S3Bucket": bucket,
                            "S3ObjectKey": source_key,
                            "PollForSourceChanges": "false",
                        },
                        "runOrder": 1,
                    }
                ],
            },
            {
                "name": "Approve",
                "actions": [
                    {
                        "name": "ApprovalAction",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                        "runOrder": 1,
                    }
                ],
            },
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
