"""e2e-pipeline-manual-approval-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pipeline-manual-approval-flow"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """End-to-end: a pipeline with a manual approval stage starts an execution, exposes
    an approval token via GetPipelineState, and approving via PutApprovalResult is the
    direct cause of the execution reaching Succeeded (approval is the last stage)."""
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

    # CreatePipeline auto-starts an initial execution of its own, and either it or the
    # execution StartPipelineExecution starts here could be the one that actually reaches
    # the Approval stage (default SUPERSEDED mode). Don't assume it's the id
    # StartPipelineExecution hands back -- read the actual driving pipelineExecutionId off
    # the stage state that carries the token.
    cp.start_pipeline_execution(name=pipeline_name)

    state = _poll_until(
        lambda: cp.get_pipeline_state(name=pipeline_name),
        lambda st: _approval_action(st).get("latestExecution", {}).get("token") is not None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    approval_stage = next(s for s in state["stageStates"] if s["stageName"] == "Approval")
    exec_id = approval_stage["latestExecution"]["pipelineExecutionId"]
    token = _approval_action(state)["latestExecution"]["token"]

    cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName="Approval",
        actionName="Approve",
        result={"summary": "sim2real behavioral check approves", "status": "Approved"},
        token=token,
    )

    final = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id)[
            "pipelineExecution"
        ],
        lambda pe: pe["status"] in ("Succeeded", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final["status"] == "Succeeded", f"expected Succeeded after approval, got {final['status']}"

    cp.delete_pipeline(name=pipeline_name)
    refusal = _error_code(lambda: cp.get_pipeline(name=pipeline_name))
    assert refusal == (
        "PipelineNotFoundException",
        f"Account '{ctx.account}' does not have a pipeline with name '{pipeline_name}'",
    ), f"expected PipelineNotFoundException after delete, got {refusal!r}"


def _approval_action(state: dict) -> dict:
    stage = next(s for s in state["stageStates"] if s["stageName"] == "Approval")
    return stage["actionStates"][0]


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


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
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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

    # CreatePipeline can transiently fail while the just-created role/policy propagates
    # through IAM; retry on the specific role-related codes, not on any error, and never
    # via a blind sleep.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            if code not in ("InvalidStructureException", "ValidationException", "InvalidRoleException"):
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(3.0)
    ctx.on_cleanup(lambda: _safe_delete_pipeline(cp, name))
    return name


def _safe_delete_pipeline(cp, name: str) -> None:
    try:
        cp.delete_pipeline(name=name)
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "PipelineNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
