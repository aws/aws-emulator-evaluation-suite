"""list-pipeline-executions-newest-first."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-pipeline-executions-newest-first"
GROUP = "ordering"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After several StartPipelineExecution calls, ListPipelineExecutions returns the
    execution summaries ordered by start time descending (most recent first)."""
    cp = ctx.client("codepipeline")
    src_type = _create_custom_action_type(ctx, "Source", 0, 0, 1, 1)
    build_type = _create_custom_action_type(ctx, "Build", 1, 1, 0, 1)
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": src_type,
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        },
        {
            "name": "Build",
            "actions": [
                {
                    "name": "BuildAction",
                    "actionTypeId": build_type,
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "outputArtifacts": [{"name": "BuildOutput"}],
                }
            ],
        },
    ]
    pipeline_name = _create_pipeline(ctx, stages)

    exec_ids = []
    for _ in range(3):
        resp = cp.start_pipeline_execution(name=pipeline_name)
        exec_ids.append(resp["pipelineExecutionId"])
        # Ensure distinct, monotonically increasing startTime values between starts.
        time.sleep(3)

    # CreatePipeline auto-triggers its own initial execution (documented AWS behavior),
    # which is older than all three of ours and must not be conflated with them here.
    exec_id_set = set(exec_ids)
    summaries = _poll_until(
        lambda: [
            s
            for s in cp.list_pipeline_executions(pipelineName=pipeline_name)[
                "pipelineExecutionSummaries"
            ]
            if s["pipelineExecutionId"] in exec_id_set
        ],
        lambda s: len(s) >= 3,
        timeout_s=60,
        interval_s=3,
    )

    returned_ids = [s["pipelineExecutionId"] for s in summaries]
    # Most recent execution (the third one started) must be first.
    assert returned_ids[0] == exec_ids[2], (returned_ids, exec_ids)
    assert returned_ids[1] == exec_ids[1], (returned_ids, exec_ids)
    assert returned_ids[2] == exec_ids[0], (returned_ids, exec_ids)

    start_times = [s["startTime"] for s in summaries[:3]]
    assert start_times[0] >= start_times[1] >= start_times[2], start_times


def _short_id() -> str:
    return uuid.uuid4().hex[:10]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            versions = s3.list_object_versions(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
            return
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_pipeline_role(ctx, bucket_name: str) -> str:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = "artifact-access"
    policy = json.dumps(
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
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_custom_action_type(ctx, category: str, min_in: int, max_in: int, min_out: int, max_out: int):
    cp = ctx.client("codepipeline")
    provider = f"S2R{category[:2]}{_short_id()}"[:35]
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": min_in, "maximumCount": max_in},
        outputArtifactDetails={"minimumCount": min_out, "maximumCount": max_out},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version)
    )
    return {"category": category, "owner": "Custom", "provider": provider, "version": version}


def _create_pipeline(ctx, stages: list[dict], pipeline_type: str = "V1") -> str:
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-")
    pipeline_def: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    if pipeline_type == "V2":
        pipeline_def["pipelineType"] = "V2"

    deadline = time.monotonic() + 30.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as e:
            err = e.response.get("Error", {})
            # Newly created IAM roles are eventually consistent, so CodePipeline can
            # reject the role as not-yet-assumable for a few seconds after creation.
            transient = err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get(
                "Message", ""
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(3)

    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
