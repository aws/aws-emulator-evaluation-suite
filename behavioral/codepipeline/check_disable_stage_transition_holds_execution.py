"""disable-stage-transition-holds-execution."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disable-stage-transition-holds-execution"
GROUP = 'lifecycle'
SERVICES = ['codepipeline']


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _account_id(ctx) -> str:
    return ctx.account


def _purge_bucket(s3, bucket) -> None:
    """Every execution writes a new version of the artifact into the store; a versioned bucket
    needs version-aware deletion or DeleteBucket fails."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _source_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", "sim2real codepipeline source artifact\n")
    return buf.getvalue()


def _artifact_store(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cpart-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=bucket, Key="source.zip", Body=_source_zip())
    return bucket


def _assumable_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cprole-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="artifacts",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                           "s3:GetBucketVersioning", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"))
    return f"arn:aws:iam::{_account_id(ctx)}:role/{name}"


def _declaration(name, role_arn, bucket):
    """Source(S3) -> Deploy(S3): a small object fetch and write in one bucket, so an execution
    cannot start a build, a deployment or a stack."""
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "executionMode": "QUEUED",
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "AWS",
                                     "provider": "S3", "version": "1"},
                    "runOrder": 1,
                    "configuration": {"S3Bucket": bucket, "S3ObjectKey": "source.zip",
                                      "PollForSourceChanges": "false"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }],
            },
            {
                "name": "Deploy",
                "actions": [{
                    "name": "DeployAction",
                    "actionTypeId": {"category": "Deploy", "owner": "AWS",
                                     "provider": "S3", "version": "1"},
                    "runOrder": 1,
                    "configuration": {"BucketName": bucket, "Extract": "false",
                                      "ObjectKey": "deployed/out.zip"},
                    "inputArtifacts": [{"name": "SourceOutput"}],
                }],
            },
        ],
    }


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=declaration)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _stage(cp, name, stage_name):
    for stage in cp.get_pipeline_state(name=name).get("stageStates", []):
        if stage.get("stageName") == stage_name:
            return stage
    return {}


def _execution_status(cp, name, execution_id):
    try:
        return cp.get_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id
        )["pipelineExecution"]["status"]
    except ClientError:
        return None


def _abandon(cp, name, execution_id):
    try:
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _execution_ids(cp, name):
    """Newest-first per the operation's contract. Returned as a LIST, never a set."""
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A disabled Inbound transition holds an execution: Source Succeeds, Deploy never starts.
    Re-enabling it lets the execution Succeed and deliver the artifact; ListPipelineExecutions is
    newest-first.

    Reference: https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_DisableStageTransition.html
    """

    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    bucket = _artifact_store(ctx)
    role_arn = _assumable_role(ctx, bucket)
    create_timeout_s = 180
    run_timeout_s = 420

    name = ctx.unique_name("sim2real-behav-cptrans-")
    _create_with_role_propagation(cp, _declaration(name, role_arn, bucket),
                                  timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    # Creating a pipeline with a source action starts an execution. Let it settle so the
    # transition test below is not racing it.
    first_ids = _poll(lambda: _execution_ids(cp, name), lambda ids: len(ids) >= 1,
                      timeout_s=run_timeout_s, interval_s=5)
    assert first_ids, "CreatePipeline started no execution and none is listed"
    first_id = first_ids[0]
    ctx.on_cleanup(lambda: _abandon(cp, name, first_id))
    first_status = _poll(
        lambda: _execution_status(cp, name, first_id),
        lambda s: s in ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded"),
        timeout_s=run_timeout_s, interval_s=5,
    )
    assert first_status == "Succeeded", (
        f"the initial execution {first_id} must reach Succeeded (Source fetch then S3 deploy), "
        f"got {first_status!r}"
    )

    # Now gate the Deploy stage's inbound transition and remove the deployed object so its
    # reappearance is unambiguous evidence of a second, real artifact hand-off.
    s3.delete_object(Bucket=bucket, Key="deployed/out.zip")
    reason = "sim2real transition hold probe"
    cp.disable_stage_transition(
        pipelineName=name, stageName="Deploy", transitionType="Inbound", reason=reason
    )
    gated = _poll(
        lambda: _stage(cp, name, "Deploy").get("inboundTransitionState", {}),
        lambda t: t.get("enabled") is False,
        timeout_s=run_timeout_s, interval_s=3,
    )
    assert gated.get("enabled") is False, (
        f"Deploy stage inboundTransitionState.enabled must be False after "
        f"DisableStageTransition, got {gated!r}"
    )
    assert gated.get("disabledReason") == reason, (
        f"disabledReason must round-trip the supplied reason, got "
        f"{gated.get('disabledReason')!r} (expected {reason!r})"
    )

    second_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    ctx.on_cleanup(lambda: _abandon(cp, name, second_id))

    # The Source stage must complete for THIS execution while the Deploy stage must not start.
    source_stage = _poll(
        lambda: _stage(cp, name, "Source"),
        lambda st: st.get("latestExecution", {}).get("pipelineExecutionId") == second_id
        and st.get("latestExecution", {}).get("status") == "Succeeded",
        timeout_s=run_timeout_s, interval_s=5,
    )
    assert source_stage.get("latestExecution", {}).get("status") == "Succeeded", (
        f"the Source stage did not Succeed for execution {second_id}: "
        f"{source_stage.get('latestExecution')!r}"
    )
    deploy_latest = _stage(cp, name, "Deploy").get("latestExecution", {})
    assert deploy_latest.get("pipelineExecutionId") != second_id, (
        f"the Deploy stage started execution {second_id} despite its Inbound transition being "
        f"disabled: {deploy_latest!r}"
    )
    assert _execution_status(cp, name, second_id) == "InProgress", (
        f"execution {second_id} must remain InProgress while held at the disabled Deploy "
        f"transition, got {_execution_status(cp, name, second_id)!r}"
    )

    # Release it: the execution must now complete and the artifact must be handed over.
    cp.enable_stage_transition(pipelineName=name, stageName="Deploy", transitionType="Inbound")
    released = _poll(
        lambda: _execution_status(cp, name, second_id),
        lambda s: s in ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded"),
        timeout_s=run_timeout_s, interval_s=5,
    )
    assert released == "Succeeded", (
        f"after EnableStageTransition, execution {second_id} must reach Succeeded, got "
        f"{released!r}"
    )
    deployed = _poll(
        lambda: [o["Key"] for o in
                 s3.list_objects_v2(Bucket=bucket, Prefix="deployed/").get("Contents", [])],
        lambda keys: "deployed/out.zip" in keys,
        timeout_s=run_timeout_s, interval_s=5,
    )
    assert "deployed/out.zip" in deployed, (
        f"the Deploy action never wrote its input artifact: objects under deployed/ are "
        f"{deployed!r}. An emulator that reports Succeeded without routing the artifact "
        f"between the two actions fails here."
    )

    # Ordering as a list, newest first (observed, not documented).
    ids = _poll(lambda: _execution_ids(cp, name), lambda i: len(i) >= 2,
                timeout_s=run_timeout_s, interval_s=3)
    assert {first_id, second_id} <= set(ids), (
        f"ListPipelineExecutions must list both executions {[first_id, second_id]}, got {ids}"
    )
    assert ids[:2] == [second_id, first_id], (
        f"ListPipelineExecutions must be newest-first: expected {[second_id, first_id]}, got "
        f"{ids[:2]} (full list {ids})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
