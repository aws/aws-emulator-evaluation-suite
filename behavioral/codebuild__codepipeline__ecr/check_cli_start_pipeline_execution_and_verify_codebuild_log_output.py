"""cli-start-pipeline-execution-and-verify-codebuild-log-output."""
from __future__ import annotations

import gzip
import hashlib
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

CHECK = "cli-start-pipeline-execution-and-verify-codebuild-log-output"
GROUP = "cli-workflow"
SERVICES = ["codebuild", "codepipeline", "ecr"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CLI-started pipeline execution drives a real CodeBuild run whose CloudWatch logs are
    retrievable and non-empty via the SDK."""
    require_tools("aws")

    ctx.client("codepipeline")
    codebuild = ctx.client("codebuild")
    logs_client = ctx.client("logs")

    pipeline_name, project_name, _source_repo, _dest_repo, _bucket = _build_stack(
        ctx, grant_ecr_push=True
    )

    exec_id = _run_aws_retry(
        ctx, "codepipeline", "start-pipeline-execution", "--name", pipeline_name
    )["pipelineExecutionId"]

    status = _wait_pipeline_execution(ctx, pipeline_name, exec_id)
    assert status == "Succeeded", f"pipeline execution ended with status={status}"

    build_id = _get_build_external_id(ctx, pipeline_name, exec_id)
    assert build_id, "no CodeBuild externalExecutionId recorded for the Build action"

    build = codebuild.batch_get_builds(ids=[build_id])["builds"][0]
    assert build["buildStatus"] == "SUCCEEDED", f"expected SUCCEEDED, got {build['buildStatus']}"
    log_info = build["logs"]
    group, stream = log_info["groupName"], log_info["streamName"]

    events = _poll_log_events(logs_client, group, stream, timeout_s=90.0)
    assert len(events) > 0, "CodeBuild log stream returned no events"
    joined = "\n".join(e["message"] for e in events)
    assert "docker push" in joined, (
        f"expected the buildspec's literal 'docker push' command to be echoed into the "
        f"CodeBuild log stream, got {len(events)} events not containing it: {joined[-500:]!r}"
    )


_BUILD_SPEC = """version: 0.2
phases:
  install:
    commands:
      - nohup dockerd --storage-driver=overlay2 > /tmp/dockerd-log.txt 2>&1 &
      - timeout 20 sh -c "until docker info >/dev/null 2>&1; do sleep 1; done" || true
  build:
    commands:
      - aws ecr get-login-password --region "$AWS_DEFAULT_REGION" | docker login --username AWS --password-stdin "$REPO_URI"
      - printf 'FROM scratch\\nCOPY imageDetail.json /imageDetail.json\\n' > Dockerfile
      - docker build -t "$REPO_URI:$IMAGE_TAG" .
      - docker push "$REPO_URI:$IMAGE_TAG"
"""



def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
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


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _run_aws_retry(ctx, *args, attempts=8, delay_s=8.0, timeout_s=30.0):
    command = ["aws", "--output", "json", *args]
    for _ in range(attempts):
        proc = _run_shell(ctx, command, timeout_s=timeout_s, check=False)
        if proc.returncode == 0:
            break
        if "InvalidStructureException" not in proc.stderr and "not authorized" not in proc.stderr:
            break
        time.sleep(delay_s)
    if proc.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={proc.returncode}):\n  cmd: {command}\n"
            f"  stderr: {proc.stderr[-500:]}"
        )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _retry(fn, attempts=8, delay_s=6.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as err:
            last_exc = err
            code = err.response["Error"]["Code"]
            if code in (
                "InvalidInputException",
                "AccessDeniedException",
                "InvalidParameterValueException",
            ):
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _empty_layer_blob():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w"):
        pass
    tar_bytes = buf.getvalue()
    diff_id = "sha256:" + hashlib.sha256(tar_bytes).hexdigest()
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    layer_bytes = gz_buf.getvalue()
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    return layer_bytes, layer_digest, diff_id


def _upload_blob(ecr, repo_name, blob_bytes, digest):
    upload = ecr.initiate_layer_upload(repositoryName=repo_name)
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload["uploadId"],
        partFirstByte=0,
        partLastByte=len(blob_bytes) - 1,
        layerPartBlob=blob_bytes,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload["uploadId"], layerDigests=[digest]
    )


def _push_minimal_image(ctx, repo_name, tag="latest"):
    ecr = ctx.client("ecr")
    layer_bytes, layer_digest, diff_id = _empty_layer_blob()
    _upload_blob(ecr, repo_name, layer_bytes, layer_digest)
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"empty_layer": True}],
    }
    config_bytes = json.dumps(config).encode()
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    _upload_blob(ecr, repo_name, config_bytes, config_digest)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag
    )
    return resp["image"]["imageId"]["imageDigest"]


def _create_ecr_repo(ctx, suffix):
    ecr = ctx.client("ecr")
    name = ctx.unique_name(f"sim2real-cpcb-{suffix}-").lower()
    resp = ecr.create_repository(
        repositoryName=name,
        imageTagMutability="MUTABLE",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    repo = resp["repository"]
    return {"name": name, "arn": repo["repositoryArn"], "uri": repo["repositoryUri"]}


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cpcb-art-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_object_versions(Bucket=name)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_role(ctx, suffix, trust_service, policy_doc):
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-cpcb-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    policy_name = f"{name}-policy"
    iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return resp["Role"]["Arn"], name


def _codebuild_policy(bucket, dest_repo_arn, grant_ecr_push):
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"],
            "Resource": f"arn:aws:s3:::{bucket}/*",
        },
    ]
    if grant_ecr_push:
        statements.append(
            {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken"], "Resource": "*"}
        )
        statements.append(
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "ecr:PutImage",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                ],
                "Resource": dest_repo_arn,
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


def _codepipeline_policy(bucket, project_names, source_repo_arn):
    project_arns = [f"arn:aws:codebuild:*:*:project/{name}" for name in project_names]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:GetBucketVersioning",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "codebuild:BatchGetBuilds",
                    "codebuild:StartBuild",
                    "codebuild:BatchGetBuildBatches",
                    "codebuild:StartBuildBatch",
                ],
                "Resource": project_arns,
            },
            {"Effect": "Allow", "Action": ["ecr:DescribeImages"], "Resource": source_repo_arn},
        ],
    }


def _pipeline_definition(pipeline_name, role_arn, bucket, source_repo_name, project_name):
    return {
        "tags": [{"key": "sim2real", "value": CHECK}],
        "pipeline": {
            "name": pipeline_name,
            "roleArn": role_arn,
            "artifactStore": {"type": "S3", "location": bucket},
            "stages": [
                {
                    "name": "Source",
                    "actions": [
                        {
                            "name": "Source",
                            "actionTypeId": {
                                "category": "Source",
                                "owner": "AWS",
                                "provider": "ECR",
                                "version": "1",
                            },
                            "outputArtifacts": [{"name": "SourceArtifact"}],
                            "configuration": {
                                "RepositoryName": source_repo_name,
                                "ImageTag": "latest",
                            },
                            "runOrder": 1,
                        }
                    ],
                },
                {
                    "name": "Build",
                    "actions": [
                        {
                            "name": "Build",
                            "actionTypeId": {
                                "category": "Build",
                                "owner": "AWS",
                                "provider": "CodeBuild",
                                "version": "1",
                            },
                            "inputArtifacts": [{"name": "SourceArtifact"}],
                            "outputArtifacts": [{"name": "BuildArtifact"}],
                            "configuration": {"ProjectName": project_name},
                            "runOrder": 1,
                        }
                    ],
                },
            ],
        }
    }


def _create_pipeline_cli(ctx, pipeline_def):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(pipeline_def, f)
        path = f.name
    try:
        _run_aws_retry(ctx, "codepipeline", "create-pipeline", "--cli-input-json", f"file://{path}")
    finally:
        os.unlink(path)


def _wait_pipeline_execution(ctx, pipeline_name, execution_id, timeout_s=900.0, interval_s=10.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cp.get_pipeline_execution(
                pipelineName=pipeline_name, pipelineExecutionId=execution_id
            )["pipelineExecution"]["status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                # freshly-started execution record can lag the StartPipelineExecution response
                # by a couple of seconds (read-after-write propagation) — retry, don't fail.
                time.sleep(interval_s)
                continue
            raise
        if status in ("Succeeded", "Failed", "Stopped", "Superseded"):
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"pipeline execution did not reach a terminal state within {timeout_s}s "
        f"(last status={status})"
    )


def _get_build_external_id(ctx, pipeline_name, execution_id):
    cp = ctx.client("codepipeline")
    resp = cp.list_action_executions(
        pipelineName=pipeline_name, filter={"pipelineExecutionId": execution_id}
    )
    for detail in resp.get("actionExecutionDetails", []):
        if detail.get("stageName") == "Build" and detail.get("actionName") == "Build":
            result = detail.get("output", {}).get("executionResult", {})
            ext_id = result.get("externalExecutionId")
            if ext_id:
                return ext_id
    return None


def _poll_log_events(logs_client, group, stream, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs_client.get_log_events(
                logGroupName=group, logStreamName=stream, startFromHead=True
            )
            events = resp.get("events", [])
            if events:
                return events
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("ResourceNotFoundException",):
                raise
        time.sleep(interval_s)
    return []


def _build_stack(ctx, grant_ecr_push):
    """Provision source/dest ECR repos, artifact bucket, roles, CodeBuild project and pipeline;
    returns (pipeline_name, project_name, source_repo, dest_repo, bucket)."""
    codebuild = ctx.client("codebuild")
    codepipeline = ctx.client("codepipeline")

    source_repo = _create_ecr_repo(ctx, "src")
    dest_repo = _create_ecr_repo(ctx, "dst")
    _push_minimal_image(ctx, source_repo["name"], tag="latest")
    bucket = _create_bucket(ctx)

    cb_role_arn, _ = _create_role(
        ctx, "cbrole", "codebuild.amazonaws.com",
        _codebuild_policy(bucket, dest_repo["arn"], grant_ecr_push=grant_ecr_push),
    )
    project_name = ctx.unique_name("sim2real-cpcb-proj-")
    _retry(
        lambda: codebuild.create_project(
            name=project_name,
            source={"type": "CODEPIPELINE", "buildspec": _BUILD_SPEC},
            artifacts={"type": "CODEPIPELINE"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "privilegedMode": True,
                "environmentVariables": [
                    {"name": "REPO_URI", "value": dest_repo["uri"]},
                    {"name": "IMAGE_TAG", "value": "pipeline-build"},
                ],
            },
            serviceRole=cb_role_arn,
            tags=[{"key": "sim2real", "value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    cp_role_arn, _ = _create_role(
        ctx, "cprole", "codepipeline.amazonaws.com",
        _codepipeline_policy(bucket, [project_name], source_repo["arn"]),
    )
    pipeline_name = ctx.unique_name("sim2real-cpcb-pipe-")
    _create_pipeline_cli(
        ctx, _pipeline_definition(pipeline_name, cp_role_arn, bucket, source_repo["name"], project_name)
    )
    ctx.on_cleanup(lambda: codepipeline.delete_pipeline(name=pipeline_name))

    return pipeline_name, project_name, source_repo, dest_repo, bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
