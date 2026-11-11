"""pipeline-role-missing-codebuild-startbuild-permission-blocks-invocation-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "pipeline-role-missing-codebuild-startbuild-permission-blocks-invocation-rejected"
GROUP = "permission-boundary"
SERVICES = ["codebuild", "codepipeline", "ecr"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipeline role without codebuild:StartBuild fails the Build action with errorDetails.code
    JobFailed and starts no build; granting the permission on the same role makes the identical
    pipeline succeed with a real build, so the failure is caused by the missing permission."""
    bucket = _create_artifact_bucket(ctx)
    codebuild_role_arn = _create_codebuild_role(ctx, bucket)
    project_name = ctx.unique_name("sim2real-cbcp-proj-")
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok\n"
    _create_codebuild_project(ctx, project_name, codebuild_role_arn, buildspec)

    # Pipeline role deliberately has S3 access but NO codebuild:* permissions at all.
    pipeline_role_name, pipeline_role_arn = _create_pipeline_role(ctx, bucket, codebuild_actions=[])
    source_key = "source.zip"
    _upload_source_zip(ctx, bucket, source_key, {"input.txt": "hello"})

    pipeline_name = ctx.unique_name("sim2real-cbcp-pipe-")
    build_config = {"ProjectName": project_name}
    _create_pipeline(ctx, pipeline_name, pipeline_role_arn, bucket, source_key, build_config)

    cp = ctx.client("codepipeline")
    cb = ctx.client("codebuild")

    execution_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    status = _wait_for_pipeline_execution(ctx, pipeline_name, execution_id)
    assert status == "Failed", f"expected Failed without codebuild:StartBuild, got {status}"

    detail = _get_action_execution(ctx, pipeline_name, execution_id, "Build", "Build")
    assert detail["status"] == "Failed", f"expected the Build action itself to be Failed, got {detail['status']!r}"
    result = detail.get("output", {}).get("executionResult", {})
    assert not result.get("externalExecutionId"), "a CodeBuild build was started despite missing permission"
    error_details = result.get("errorDetails") or {}
    assert error_details.get("code") == "JobFailed", (
        f"expected the Build action to report errorDetails.code JobFailed for the missing "
        f"codebuild:StartBuild permission, got {error_details!r} (full result {result!r})"
    )
    ids_without_permission = cb.list_builds_for_project(projectName=project_name)["ids"]
    assert ids_without_permission == [], (
        f"no CodeBuild build should ever have been created for {project_name!r} without "
        f"codebuild:StartBuild, got ids {ids_without_permission!r}"
    )

    # Positive control: grant the missing permission on the SAME role, then retry.
    fix_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "codebuild:StartBuild",
                    "codebuild:BatchGetBuilds",
                    "codebuild:StartBuildBatch",
                    "codebuild:BatchGetBuildBatches",
                ],
                "Resource": f"arn:aws:codebuild:{ctx.region}:{_account_id(ctx)}:project/*",
            }
        ],
    }
    iam = ctx.client("iam")
    iam.put_role_policy(RoleName=pipeline_role_name, PolicyName="fix-codebuild-access", PolicyDocument=json.dumps(fix_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=pipeline_role_name, PolicyName="fix-codebuild-access"))

    # The put_role_policy call above returns immediately, but IAM permission propagation into
    # CodePipeline's internal use of the role (to call codebuild:StartBuild on our behalf) can lag
    # by tens of seconds. A single execution attempt can still fail with "Failed" purely due to
    # that propagation delay, not because the permission is actually missing -- so retry the whole
    # start+wait cycle (not just the start call) until it succeeds or we give up.
    deadline = time.monotonic() + 90.0
    status_2 = None
    execution_id_2 = None
    while time.monotonic() < deadline:
        execution_id_2 = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
        status_2 = _wait_for_pipeline_execution(ctx, pipeline_name, execution_id_2, timeout_s=120.0)
        if status_2 == "Succeeded":
            break
        time.sleep(2)
    assert status_2 == "Succeeded", f"expected Succeeded after granting codebuild:StartBuild, got {status_2}"
    ids_with_permission = cb.list_builds_for_project(projectName=project_name)["ids"]
    assert ids_with_permission != [], (
        f"granting codebuild:StartBuild should have produced a real CodeBuild build for "
        f"{project_name!r}, got no ids"
    )


# ===== helpers =====

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


def _create_codebuild_project(ctx, name: str, role_arn: str, buildspec: str) -> str:
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
    _retry_iam_propagation(
        lambda: cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}])
    )
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
                # newly-started execution not yet visible (eventual consistency) — retry
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
