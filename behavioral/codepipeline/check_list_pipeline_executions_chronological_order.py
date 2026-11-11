"""list-pipeline-executions-chronological-order."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "list-pipeline-executions-chronological-order"
GROUP = "ordering"
SERVICES = ["codepipeline"]
_SCENARIO = CHECK


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListPipelineExecutions returns three started executions in exactly the reverse of their start order, with
    startTime sorted most recent first.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    pipeline_name = _create_pipeline(
        ctx,
        role_arn,
        bucket,
        stages=[
            _source_stage(bucket),
            {
                "name": "Approval",
                "actions": [
                    {
                        "name": "Approve",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                    }
                ],
            },
        ],
    )

    started_ids = []
    for _ in range(3):
        exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
        started_ids.append(exec_id)
        time.sleep(2.0)

    started_id_set = set(started_ids)
    summaries = _poll_until(
        lambda: cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"],
        lambda summs: started_id_set <= {s["pipelineExecutionId"] for s in summs},
        timeout_s=60.0,
        interval_s=3.0,
    )

    listed_ids = [s["pipelineExecutionId"] for s in summaries if s["pipelineExecutionId"] in started_ids]
    assert listed_ids == list(reversed(started_ids)), (
        f"expected most-recent-first order {list(reversed(started_ids))}, got {listed_ids}"
    )

    # Timestamps themselves must be non-increasing across the whole returned page.
    times = [s["startTime"] for s in summaries]
    assert times == sorted(times, reverse=True), "startTime values are not sorted most-recent-first"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral check source artifact")
    return buf.getvalue()


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 rejects an explicit LocationConstraint for its own region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=_zip_bytes())
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "artifact-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:GetBucketVersioning",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _source_stage(bucket: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "configuration": {
                    "S3Bucket": bucket,
                    "S3ObjectKey": "source.zip",
                    "PollForSourceChanges": "false",
                },
                "outputArtifacts": [{"name": "SourceOutput"}],
            }
        ],
    }


def _create_pipeline(ctx, role_arn: str, bucket: str, stages: list, pipeline_type=None) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pl-")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    if pipeline_type:
        pipeline["pipelineType"] = pipeline_type

    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": _SCENARIO}])
            break
        except Exception:  # IAM role/trust-policy propagation is eventually consistent
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
