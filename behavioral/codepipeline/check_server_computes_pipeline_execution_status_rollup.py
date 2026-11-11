"""server-computes-pipeline-execution-status-rollup."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-computes-pipeline-execution-status-rollup"
GROUP = "server-side"
SERVICES = ["codepipeline"]
_SCENARIO = "codepipeline-server-computes-status-rollup"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetPipelineExecution and ListPipelineExecutions both report InProgress while a manual approval is
    outstanding and both report Failed after the approval is rejected.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, bucket)
    _upload_source_zip(ctx, bucket, "source.zip")

    name = ctx.unique_name("sim2real-cp-rollup-")
    stages = [
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
                    "configuration": {
                        "S3Bucket": bucket,
                        "S3ObjectKey": "source.zip",
                        "PollForSourceChanges": "false",
                    },
                    "outputArtifacts": [{"name": "SourceOutput"}],
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
                }
            ],
        },
    ]
    _create_pipeline(ctx, name, role_arn, bucket, stages)

    # CreatePipeline auto-triggers its own initial execution; use that one rather
    # than calling StartPipelineExecution again, which would just queue a second,
    # superseded execution behind the one already occupying the Approval action.
    execution_id = _wait_for_sole_execution_id(ctx, name, timeout_s=60)

    token = _wait_for_approval_token(ctx, name, "Approve", "ApprovalAction", timeout_s=120)

    exec_details = cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=execution_id)
    got = exec_details["pipelineExecution"]["status"]
    assert got == "InProgress", f"expected GetPipelineExecution status InProgress while approval is outstanding, got {got}"

    summaries = cp.list_pipeline_executions(pipelineName=name)["pipelineExecutionSummaries"]
    summary = next(s for s in summaries if s["pipelineExecutionId"] == execution_id)
    assert summary["status"] == "InProgress", (
        f"expected ListPipelineExecutions status InProgress while approval is outstanding, got {summary['status']}"
    )

    cp.put_approval_result(
        pipelineName=name,
        stageName="Approve",
        actionName="ApprovalAction",
        result={"summary": "rejected by behavioral fidelity check", "status": "Rejected"},
        token=token,
    )

    _wait_for_stage_status(ctx, name, "Approve", "Failed", timeout_s=150)

    final_exec = _wait_for_execution_status(ctx, name, execution_id, "Failed", timeout_s=150)
    assert final_exec["status"] == "Failed", (
        f"expected GetPipelineExecution status Failed after the approval was rejected, got {final_exec['status']}"
    )

    final_summaries = cp.list_pipeline_executions(pipelineName=name)["pipelineExecutionSummaries"]
    final_summary = next(s for s in final_summaries if s["pipelineExecutionId"] == execution_id)
    assert final_summary["status"] == "Failed", (
        f"expected ListPipelineExecutions status Failed after the approval was rejected, got {final_summary['status']}"
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-rollup-").lower().replace("_", "-")
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        objs = s3.list_object_versions(Bucket=bucket)
        to_delete = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in objs.get("Versions", []) + objs.get("DeleteMarkers", [])
        ]
        if to_delete:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": to_delete}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_source_zip(ctx, bucket, key):
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral check artifact")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _create_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-s3"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    # IAM roles/policies can take a short time to propagate before another service can
    # assume them: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    # No fixed extra sleep beyond this existence check: the pipeline's own bounded waits
    # for its first execution and approval token (below) already absorb any residual
    # assume-role propagation delay before the Source action actually runs.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if iam.get_role(RoleName=role_name)["Role"]["RoleName"] == role_name:
            break
        time.sleep(1)
    return role["Arn"]


def _create_pipeline(ctx, name, role_arn, bucket, stages):
    cp = ctx.client("codepipeline")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    result = _create_with_role_propagation(cp, pipeline, timeout_s=60)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return result


def _create_with_role_propagation(cp, pipeline, *, timeout_s):
    # A freshly created role's trust policy can take a few seconds to become
    # assumable by codepipeline.amazonaws.com; CreatePipeline validates AssumeRole
    # synchronously, so retry on exactly that transient error instead of guessing
    # a fixed pre-delay.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": _SCENARIO}])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (
                err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _wait_for_stage_status(ctx, pipeline_name, stage_name, expected_status, *, timeout_s=120.0, interval_s=5.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        state = cp.get_pipeline_state(name=pipeline_name)
        stage = next(s for s in state["stageStates"] if s["stageName"] == stage_name)
        last = stage.get("latestExecution", {}).get("status")
        if last == expected_status:
            return
        time.sleep(interval_s)
    raise AssertionError(f"stage {stage_name} never reached {expected_status}, last saw {last}")


def _wait_for_approval_token(ctx, pipeline_name, stage_name, action_name, *, timeout_s=120.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = cp.get_pipeline_state(name=pipeline_name)
        stage = next(s for s in state["stageStates"] if s["stageName"] == stage_name)
        action = next(
            (a for a in stage.get("actionStates", []) if a["actionName"] == action_name), None
        )
        latest = (action or {}).get("latestExecution", {})
        if latest.get("token"):
            return latest["token"]
        time.sleep(interval_s)
    raise AssertionError(f"approval token for {action_name} never appeared within {timeout_s}s")


def _wait_for_execution_status(ctx, pipeline_name, execution_id, expected_status, *, timeout_s=60.0, interval_s=5.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        exec_details = cp.get_pipeline_execution(
            pipelineName=pipeline_name, pipelineExecutionId=execution_id
        )["pipelineExecution"]
        last = exec_details["status"]
        if last == expected_status:
            return exec_details
        time.sleep(interval_s)
    raise AssertionError(f"execution never reached {expected_status}, last saw {last}")


def _wait_for_sole_execution_id(ctx, pipeline_name, *, timeout_s=60.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summaries = cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"]
        if summaries:
            return summaries[0]["pipelineExecutionId"]
        time.sleep(interval_s)
    raise AssertionError(f"no pipeline execution appeared for {pipeline_name} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
