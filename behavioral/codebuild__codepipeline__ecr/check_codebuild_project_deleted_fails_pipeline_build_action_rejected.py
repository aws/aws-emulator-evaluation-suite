"""codebuild-project-deleted-fails-pipeline-build-action-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "codebuild-project-deleted-fails-pipeline-build-action-rejected"
GROUP = "permission-boundary"
SERVICES = ["codebuild", "codepipeline", "ecr"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipeline Build action naming a deleted CodeBuild project fails with an errorDetails code
    and starts no build; re-pointing the pipeline at an existing project succeeds with one build.
    """
    bucket = _create_artifact_bucket(ctx)
    codebuild_role_arn = _create_codebuild_role(ctx, bucket)
    project_a = ctx.unique_name("sim2real-cbcp-proj-")
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok\n"
    _create_codebuild_project(ctx, project_a, codebuild_role_arn, buildspec, register_cleanup=False)

    _, pipeline_role_arn = _create_pipeline_role(ctx, bucket)
    source_key = "source.zip"
    _upload_source_zip(ctx, bucket, source_key, {"input.txt": "hello"})

    pipeline_name = ctx.unique_name("sim2real-cbcp-pipe-")
    build_config = {"ProjectName": project_a}
    _create_pipeline(ctx, pipeline_name, pipeline_role_arn, bucket, source_key, build_config)

    cp = ctx.client("codepipeline")
    cb = ctx.client("codebuild")

    cb.delete_project(name=project_a)

    gone = cb.batch_get_projects(names=[project_a])
    assert project_a in gone.get("projectsNotFound", []), (
        f"deleted project {project_a!r} must be reported not-found by BatchGetProjects, "
        f"got projectsNotFound={gone.get('projectsNotFound')!r} projects={gone.get('projects')!r}"
    )

    execution_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    status = _wait_for_pipeline_execution(ctx, pipeline_name, execution_id)
    assert status == "Failed", f"expected Failed against a deleted project, got {status}"

    detail = _get_action_execution(ctx, pipeline_name, execution_id, "Build", "Build")
    assert detail["status"] == "Failed", f"expected the Build action itself to be Failed, got {detail['status']!r}"
    result = detail.get("output", {}).get("executionResult", {})
    assert not result.get("externalExecutionId"), "a CodeBuild build was started against a deleted project"
    error_details = result.get("errorDetails") or {}
    error_code = error_details.get("code")
    assert error_code, (
        f"the Build action failure must report a specific errorDetails.code identifying the "
        f"cause, got errorDetails={error_details!r} (full result {result!r})"
    )

    # Positive control: point the same pipeline at a fresh project and retry.
    project_b = ctx.unique_name("sim2real-cbcp-proj-")
    _create_codebuild_project(ctx, project_b, codebuild_role_arn, buildspec)

    pipeline_def = cp.get_pipeline(name=pipeline_name)["pipeline"]
    pipeline_def["stages"][1]["actions"][0]["configuration"]["ProjectName"] = project_b
    cp.update_pipeline(pipeline=pipeline_def)

    execution_id_2 = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    status_2 = _wait_for_pipeline_execution(ctx, pipeline_name, execution_id_2)
    assert status_2 == "Succeeded", f"expected Succeeded once pointed at an existing project, got {status_2}"
    builds = cb.list_builds_for_project(projectName=project_b)["ids"]
    assert len(builds) == 1, f"expected exactly one CodeBuild build for the fresh project, got {builds!r}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cbcp-art-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        versions = s3.list_object_versions(Bucket=name)
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


def _upload_source_zip(ctx, bucket: str, key: str, files: dict[str, str]) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _create_codebuild_role(ctx, bucket: str, trust_service: str = "codebuild.amazonaws.com") -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cbcp-cbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return role_arn


def _create_pipeline_role(ctx, bucket: str, codebuild_actions: list[str] | None = None) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cbcp-cprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    actions = (
        codebuild_actions
        if codebuild_actions is not None
        else ["codebuild:StartBuild", "codebuild:BatchGetBuilds", "codebuild:StartBuildBatch", "codebuild:BatchGetBuildBatches"]
    )
    statements = [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:GetBucketVersioning", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        },
    ]
    if actions:
        statements.append(
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": f"arn:aws:codebuild:{ctx.region}:{_account_id(ctx)}:project/*",
            }
        )
    policy = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, role_arn


def _retry_iam_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            msg = str(exc)
            code = exc.response.get("Error", {}).get("Code", "")
            if "AssumeRole" in msg or "not authorized" in msg or code == "InvalidStructureException":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"operation never succeeded after IAM propagation wait: {last_exc}")


def _create_codebuild_project(ctx, name: str, role_arn: str, buildspec: str, register_cleanup: bool = True) -> str:
    cb = ctx.client("codebuild")

    def _do():
        resp = cb.create_project(
            name=name,
            source={"type": "CODEPIPELINE", "buildspec": buildspec},
            artifacts={"type": "CODEPIPELINE"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=role_arn,
            tags=[{"key": "sim2real", "value": CHECK}],
        )
        return resp["project"]["arn"]

    arn = _retry_iam_propagation(_do)
    if register_cleanup:
        ctx.on_cleanup(lambda: cb.delete_project(name=name))
    return arn


def _create_pipeline(
    ctx,
    pipeline_name: str,
    role_arn: str,
    bucket: str,
    source_key: str,
    build_config: dict[str, str],
    build_output_artifacts: list[dict[str, str]] | None = None,
) -> None:
    cp = ctx.client("codepipeline")
    pipeline_tags = [{"key": "sim2real", "value": CHECK}]
    pipeline = {
        "name": pipeline_name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "Source",
                        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                        "configuration": {
                            "S3Bucket": bucket,
                            "S3ObjectKey": source_key,
                            "PollForSourceChanges": "false",
                        },
                        "outputArtifacts": [{"name": "SourceOutput"}],
                        "inputArtifacts": [],
                    }
                ],
            },
            {
                "name": "Build",
                "actions": [
                    {
                        "name": "Build",
                        "actionTypeId": {"category": "Build", "owner": "AWS", "provider": "CodeBuild", "version": "1"},
                        "configuration": build_config,
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "outputArtifacts": build_output_artifacts or [],
                    }
                ],
            },
        ],
    }
    _retry_iam_propagation(lambda: cp.create_pipeline(pipeline=pipeline, tags=pipeline_tags))
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))


def _wait_for_pipeline_execution(ctx, pipeline_name: str, execution_id: str, timeout_s: float = 480.0) -> str:
    from botocore.exceptions import ClientError

    cp = ctx.client("codepipeline")
    terminal = {"Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"}
    deadline = time.monotonic() + timeout_s
    status = "InProgress"
    while time.monotonic() < deadline:
        try:
            status = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)[
                "pipelineExecution"
            ]["status"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "PipelineExecutionNotFoundException":
                # A newly started execution is not yet visible (eventual consistency).
                time.sleep(3)
                continue
            raise
        if status in terminal:
            return status
        time.sleep(5)
    raise AssertionError(f"pipeline execution did not reach terminal status in {timeout_s}s (last={status})")


def _get_action_execution(ctx, pipeline_name: str, execution_id: str, stage_name: str, action_name: str) -> dict:
    cp = ctx.client("codepipeline")
    resp = cp.list_action_executions(pipelineName=pipeline_name, filter={"pipelineExecutionId": execution_id})
    for detail in resp.get("actionExecutionDetails", []):
        if detail["stageName"] == stage_name and detail["actionName"] == action_name:
            return detail
    raise AssertionError(f"no action execution found for {stage_name}/{action_name}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
