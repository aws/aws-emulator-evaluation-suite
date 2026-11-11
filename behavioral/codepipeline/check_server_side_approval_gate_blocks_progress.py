"""server-side-approval-gate-blocks-progress."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-approval-gate-blocks-progress"
GROUP = "server-side"
SERVICES = ["codepipeline"]
_SCENARIO = CHECK


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The managed executor halts a live execution at a manual approval action
    until PutApprovalResult is submitted, does not let a later stage start while
    the approval is outstanding, and automatically resumes once approved."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _upload_source_zip(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-approvegate-")

    pipeline_def = _three_stage_pipeline(name, role_arn, bucket, key)
    _wait_role_usable(
        lambda: cp.create_pipeline(
            pipeline=pipeline_def, tags=[{"key": "sim2real", "value": _SCENARIO}]
        )
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    def _probe() -> dict:
        return cp.get_pipeline_state(name=name)

    # NOTE: CreatePipeline itself auto-starts an initial execution (the
    # "CreatePipeline" trigger type) independent of the StartPipelineExecution
    # call below. Two concurrent executions racing through the same approval
    # gates makes stage-level "latestExecution" state ambiguous (it always
    # reflects whichever execution touched the stage most recently, including a
    # trailing/superseded one). Drain that auto-triggered execution to
    # completion first so the explicit StartPipelineExecution below is the only
    # execution in flight for the actual assertions.
    _drain_pending_approvals(cp, name, _probe, timeout_s=180.0)

    # Baseline, taken after the drain and before our own execution starts: this
    # is what "Final" looked like when nothing of ours was in flight yet. The
    # drain leaves it pointing at the auto-triggered execution it just finished
    # draining, never at the execution we are about to start.
    final_baseline = _action_state(_probe(), "Final", "SecondApproval").get("latestExecution", {})

    cp.start_pipeline_execution(name=name)

    gated = _poll_until(
        _probe,
        lambda s: _action_state(s, "Gate", "FirstApproval").get("latestExecution", {}).get(
            "status"
        )
        == "InProgress",
        timeout_s=120.0,
    )
    exec_id = _stage_state(gated, "Gate")["latestExecution"]["pipelineExecutionId"]
    token = _action_state(gated, "Gate", "FirstApproval")["latestExecution"]["token"]

    # While gated, the downstream stage must not have moved *at all*: comparing
    # only the status for our own exec_id is vacuous here, because "Final"'s
    # latestExecution cannot report our exec_id until Final has actually
    # started for it -- which is exactly the thing under test. Asserting
    # equality against the pre-start baseline is unconditional: it fails the
    # instant Final's latestExecution changes to anything else, ours included.
    final_latest = _action_state(gated, "Final", "SecondApproval").get("latestExecution", {})
    assert final_latest == final_baseline, (
        f"Final's latestExecution changed while Gate/FirstApproval for execution "
        f"{exec_id} was still outstanding: baseline {final_baseline!r} -> now {final_latest!r}"
    )

    cp.put_approval_result(
        pipelineName=name,
        stageName="Gate",
        actionName="FirstApproval",
        result={"status": "Approved", "summary": "behavioral-fidelity approve"},
        token=token,
    )

    resumed = _poll_until(
        _probe,
        lambda s: _action_state(s, "Final", "SecondApproval")
        .get("latestExecution", {})
        .get("status")
        == "InProgress",
        timeout_s=120.0,
    )
    # With the auto-triggered execution already drained above, this is now the
    # only execution in flight, so Gate's stage-level state is unambiguously
    # ours and settles to Succeeded quickly once Final has started.
    gate_stage = _stage_state(resumed, "Gate")
    gate_latest = gate_stage["latestExecution"]
    assert gate_latest["status"] == "Succeeded", (
        f"Gate should have settled to Succeeded once Final started, got {gate_latest!r}"
    )

    final_token = _action_state(resumed, "Final", "SecondApproval")["latestExecution"]["token"]
    cp.put_approval_result(
        pipelineName=name,
        stageName="Final",
        actionName="SecondApproval",
        result={"status": "Approved", "summary": "behavioral-fidelity approve"},
        token=final_token,
    )

    def _probe_execution() -> dict:
        return cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=exec_id)[
            "pipelineExecution"
        ]

    # As above: settle the last action's own state first (fast), then wait on
    # the slower-to-aggregate execution-level status.
    final_settled = _poll_until(
        _probe,
        lambda s: _action_state(s, "Final", "SecondApproval")
        .get("latestExecution", {})
        .get("status")
        in ("Succeeded", "Failed"),
        timeout_s=120.0,
    )
    final_action_status = _action_state(final_settled, "Final", "SecondApproval")[
        "latestExecution"
    ]["status"]
    assert final_action_status == "Succeeded", (
        f"expected Final/SecondApproval to settle to Succeeded, got {final_action_status!r}"
    )

    final_exec = _poll_until(
        _probe_execution, lambda e: e["status"] in ("Succeeded", "Failed"), timeout_s=240.0
    )
    assert final_exec["status"] == "Succeeded", (
        f"expected pipeline execution {exec_id} to reach Succeeded, got {final_exec['status']!r}"
    )


def _stage_state(state_resp: dict, stage_name: str) -> dict:
    for stage in state_resp["stageStates"]:
        if stage["stageName"] == stage_name:
            return stage
    raise AssertionError(f"stage {stage_name} not found")


def _action_state(state_resp: dict, stage_name: str, action_name: str) -> dict:
    stage = _stage_state(state_resp, stage_name)
    for action in stage["actionStates"]:
        if action["actionName"] == action_name:
            return action
    raise AssertionError(f"action {action_name} not found in stage {stage_name}")


def _drain_pending_approvals(cp, name: str, probe, *, timeout_s: float = 180.0) -> None:
    """Approve every InProgress manual-approval action as it appears, until the
    auto-triggered execution from CreatePipeline runs to completion (its last
    stage's action reaches a terminal status) or clearly can't get there (Source
    failed). Best-effort and non-fatal on timeout -- this is just draining
    pre-existing state so the real assertions below have a single execution in
    flight, not the thing under test."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = probe()
        final_status = _action_state(state, "Final", "SecondApproval").get(
            "latestExecution", {}
        ).get("status")
        if final_status in ("Succeeded", "Failed"):
            return
        source_status = _stage_state(state, "Source").get("latestExecution", {}).get("status")
        if source_status == "Failed":
            return
        gate_status = _action_state(state, "Gate", "FirstApproval").get(
            "latestExecution", {}
        ).get("status")
        if gate_status == "InProgress":
            token = _action_state(state, "Gate", "FirstApproval")["latestExecution"]["token"]
            cp.put_approval_result(
                pipelineName=name,
                stageName="Gate",
                actionName="FirstApproval",
                result={"status": "Approved", "summary": "behavioral-fidelity drain"},
                token=token,
            )
        elif final_status == "InProgress":
            token = _action_state(state, "Final", "SecondApproval")["latestExecution"]["token"]
            cp.put_approval_result(
                pipelineName=name,
                stageName="Final",
                actionName="SecondApproval",
                result={"status": "Approved", "summary": "behavioral-fidelity drain"},
                token=token,
            )
        time.sleep(3)


def _poll_until(probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


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
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]}
    )

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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
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


def _three_stage_pipeline(name: str, role_arn: str, bucket: str, source_key: str) -> dict:
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
                "name": "Gate",
                "actions": [
                    {
                        "name": "FirstApproval",
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
            {
                "name": "Final",
                "actions": [
                    {
                        "name": "SecondApproval",
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
