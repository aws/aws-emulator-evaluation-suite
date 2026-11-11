"""list-pipeline-executions-reverse-chronological-order."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-pipeline-executions-reverse-chronological-order"
GROUP = "ordering"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Multiple StartPipelineExecution calls come back from ListPipelineExecutions
    in strict most-recent-first order, matching AWS's documented "most recent
    executions" contract -- not creation-id or any other stable ordering."""
    role_arn = _iam_role_arn(ctx)
    artifact_bucket = _artifact_bucket(ctx)
    source_bucket = _source_bucket(ctx)
    name = ctx.unique_name("sim2real-cp-ord-")
    _create_pipeline(
        ctx,
        name,
        role_arn,
        artifact_bucket,
        source_bucket,
        stage2_actions=[
            {
                "name": "ApprovalAction",
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                "runOrder": 1,
            }
        ],
    )

    cp = ctx.client("codepipeline")
    exec_ids = []
    for _ in range(3):
        resp = cp.start_pipeline_execution(name=name)
        exec_ids.append(resp["pipelineExecutionId"])
        # Space the starts apart so each gets a distinguishable startTime -- this is
        # pacing, not a wait for any condition, so it is not a candidate for a poll.
        time.sleep(2)

    assert len(set(exec_ids)) == 3, f"expected 3 distinct execution ids, got {exec_ids}"

    # CreatePipeline auto-triggers an initial execution of its own (well documented AWS
    # behavior), so ListPipelineExecutions for this pipeline will show that extra, older
    # execution alongside our 3. Poll until at least our 3 have landed (ListPipelineExecutions
    # can lag StartPipelineExecution slightly), then check ordering only among OUR executions
    # -- ignoring any auto-triggered execution is exactly the point: it must sort as OLDER
    # than all 3 of ours, which is itself part of what "most-recent-first" ordering implies.
    exec_id_set = set(exec_ids)
    deadline = time.monotonic() + 60
    listed_ids: list[str] = []
    ours_in_listed: list[str] = []
    while time.monotonic() < deadline:
        listed = cp.list_pipeline_executions(pipelineName=name, maxResults=10)["pipelineExecutionSummaries"]
        listed_ids = [s["pipelineExecutionId"] for s in listed]
        ours_in_listed = [eid for eid in listed_ids if eid in exec_id_set]
        if len(ours_in_listed) == 3:
            break
        time.sleep(3)

    assert len(ours_in_listed) == 3, (
        f"expected all 3 of our executions to appear in ListPipelineExecutions after polling, "
        f"got {ours_in_listed} within full list {listed_ids}"
    )
    assert ours_in_listed == list(reversed(exec_ids)), (
        f"ListPipelineExecutions order of our executions {ours_in_listed} does not match "
        f"most-recent-first of start order {exec_ids}"
    )


# ===== helpers =====

def _iam_role_arn(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-cp-inline",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cp-inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _artifact_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-artifacts-")
    kwargs: dict[str, Any] = {}
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for -- this
    # is an S3 API quirk, not a region pin on the check itself (ctx.region drives it).
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _source_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-source-")
    kwargs: dict[str, Any] = {}
    # Same S3 quirk as _artifact_bucket: us-east-1 rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=name, Key="source.zip", Body=b"PK\x05\x06" + b"\x00" * 18)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        versions = s3.list_object_versions(Bucket=name)
        delete_list = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        delete_list += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])]
        if delete_list:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": delete_list}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_pipeline(
    ctx: Any,
    name: str,
    role_arn: str,
    artifact_bucket: str,
    source_bucket: str,
    stage2_actions: list[dict[str, Any]],
    execution_mode: str | None = None,
    pipeline_type: str | None = None,
    stage2_before_entry: dict[str, Any] | None = None,
    source_namespace: str | None = None,
) -> dict[str, Any]:
    cp = ctx.client("codepipeline")
    source_action: dict[str, Any] = {
        "name": "SourceAction",
        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
        "configuration": {"S3Bucket": source_bucket, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"},
        "outputArtifacts": [{"name": "SourceOutput"}],
        "runOrder": 1,
    }
    if source_namespace:
        source_action["namespace"] = source_namespace
    stage2: dict[str, Any] = {"name": "Approve", "actions": stage2_actions}
    if stage2_before_entry:
        stage2["beforeEntry"] = stage2_before_entry
    pipeline_def: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [{"name": "Source", "actions": [source_action]}, stage2],
    }
    if execution_mode:
        pipeline_def["executionMode"] = execution_mode
    if pipeline_type:
        pipeline_def["pipelineType"] = pipeline_type

    resp = None
    last_err: Exception | None = None
    for attempt in range(10):
        try:
            resp = cp.create_pipeline(pipeline=pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as e:
            last_err = e
            if attempt < 9:
                time.sleep(3)
                continue
            raise
    assert resp is not None, str(last_err)
    ctx.on_cleanup(lambda: _delete_pipeline_quiet(ctx, name))
    return resp["pipeline"]


def _delete_pipeline_quiet(ctx: Any, name: str) -> None:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.delete_pipeline(name=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "PipelineNotFoundException":
                return
            if code != "ConcurrentModificationException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
