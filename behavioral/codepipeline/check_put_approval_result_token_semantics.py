"""put-approval-result-token-semantics."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-approval-result-token-semantics"
GROUP = 'lifecycle'
SERVICES = ['codepipeline']

_SCENARIO = 'codepipeline-put-approval-result-token-semantics'


# PutApprovalResult raises FOUR distinct
# faults, and which one you get is decided by WHICH part of the address is wrong -- the whole
# taxonomy is asserted below because an emulator that returns one catch-all error for every bad
# approval satisfies any single-code assertion:
#   unknown stage name            -> StageNotFoundException
#   unknown action within a stage -> ActionNotFoundException
#   a real action that is not an approval action -> InvalidApprovalTokenException
#   a real approval action, wrong token          -> InvalidApprovalTokenException
# The last two SHARE a code, so the messages are the only discriminator and are asserted.
_ERR_TOKEN = "InvalidApprovalTokenException"
_ERR_STAGE = "StageNotFoundException"
_ERR_ACTION = "ActionNotFoundException"


# ===== helpers =====

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
    """DeletePipeline does NOT delete the artifact store, and every execution writes a new
    version into it, so DeleteBucket needs version-aware deletion."""
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
    """A versioned S3 artifact store holding the source object. Teardown is registered before
    anything that depends on it, so LIFO cleanup purges it last."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cpart-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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
    """Source(S3) -> Approval(Manual). A manual-approval stage is the cheapest way to hold a
    pipeline in a real, observable non-terminal state: it launches nothing, provisions nothing,
    and has no downstream resources to leak."""
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
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
                "name": "Gate",
                "actions": [{
                    "name": "ApproveAction",
                    "actionTypeId": {"category": "Approval", "owner": "AWS",
                                     "provider": "Manual", "version": "1"},
                    "runOrder": 1,
                }],
            },
        ],
    }


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(
                pipeline=declaration,
                tags=[{"key": "sim2real", "value": _SCENARIO}],
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _gate_action_state(cp, name):
    for stage in cp.get_pipeline_state(name=name).get("stageStates", []):
        if stage.get("stageName") == "Gate":
            for action in stage.get("actionStates", []):
                if action.get("actionName") == "ApproveAction":
                    return action
    return {}


def _execution_status(cp, name, execution_id):
    try:
        return cp.get_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id
        )["pipelineExecution"]["status"]
    except ClientError:
        return None


def _abandon(cp, name, execution_id):
    """Best-effort: never leave an execution parked at an approval gate accruing
    action-execution-minutes after the check ends."""
    try:
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutApprovalResult with a wrong token is refused with InvalidApprovalTokenException and
    does not advance the execution, the correct token advances it to Succeeded, and replaying
    the consumed token is refused with ApprovalAlreadyCompletedException."""

    cp = ctx.client("codepipeline")
    bucket = _artifact_store(ctx)
    role_arn = _assumable_role(ctx, bucket)
    create_timeout_s = 180
    run_timeout_s = 420

    name = ctx.unique_name("sim2real-behav-cpappr-")
    _create_with_role_propagation(cp, _declaration(name, role_arn, bucket),
                                  timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    # Creating a pipeline with a source action starts an execution. Wait for it to arrive at
    # the approval gate and mint a token.
    action = _poll(
        lambda: _gate_action_state(cp, name),
        lambda a: a.get("latestExecution", {}).get("status") == "InProgress"
        and bool(a.get("latestExecution", {}).get("token")),
        timeout_s=run_timeout_s, interval_s=5,
    )
    latest = action.get("latestExecution", {})
    assert latest.get("status") == "InProgress", (
        f"the Gate approval action never reached InProgress; latestExecution={latest!r}. "
        f"An emulator that does not advance an execution out of the Source stage fails here."
    )
    token = latest.get("token")
    assert token, f"the approval action reported no token: {latest!r}"

    summaries = cp.list_pipeline_executions(pipelineName=name)["pipelineExecutionSummaries"]
    assert len(summaries) == 1, (
        f"expected exactly one execution after CreatePipeline, got "
        f"{[s['pipelineExecutionId'] for s in summaries]}"
    )
    execution_id = summaries[0]["pipelineExecutionId"]
    ctx.on_cleanup(lambda: _abandon(cp, name, execution_id))
    assert summaries[0]["status"] == "InProgress", (
        f"execution {execution_id} should be InProgress while parked at the approval gate, "
        f"got {summaries[0]['status']!r}"
    )

    # Break exactly one thing: submit a syntactically valid but wrong token.
    wrong_token = "00000000-0000-0000-0000-000000000000"
    assert wrong_token != token, "the fabricated wrong token collided with the real one"
    try:
        cp.put_approval_result(
            pipelineName=name, stageName="Gate", actionName="ApproveAction",
            token=wrong_token,
            result={"summary": "sim2real wrong-token probe", "status": "Approved"},
        )
        raise AssertionError("PutApprovalResult accepted a token that is not the current approval token")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, msg = err.get("Code"), err.get("Message") or ""
    # AWS wraps the token in U+2018/U+2019 curly quotes.
    expected_msg = (
        f"Approval token \u2018{wrong_token}\u2019 either does not exist or is not the correct "
        "token for action ApproveAction and stage Gate."
    )
    assert (code, msg) == (_ERR_TOKEN, expected_msg), (
        f"the refusal must be {_ERR_TOKEN} about the TOKEN, naming the action and stage it was "
        f"checked against: {(code, msg)!r}"
    )

    # Effect absent: the refused approval must not have advanced anything.
    still = _gate_action_state(cp, name).get("latestExecution", {})
    assert still.get("status") == "InProgress", (
        f"the Gate action advanced to {still.get('status')!r} despite the approval being "
        f"refused -- the wrong token was honoured"
    )
    assert _execution_status(cp, name, execution_id) == "InProgress", (
        f"execution {execution_id} left InProgress after a refused approval: "
        f"{_execution_status(cp, name, execution_id)!r}"
    )

    # The CORRECT token, addressed to a real action that is not an approval action. Real
    # CodePipeline does NOT report this as ActionNotFoundException: the action exists, so the lookup succeeds and the request fails as an
    # invalid TOKEN -- InvalidApprovalTokenException, "<pipeline> does not include an approval
    # action named SourceAction." A valid token is therefore scoped to one specific approval
    # action and is worthless anywhere else, which the control below completes by using the very
    # same token successfully on Gate/ApproveAction.
    def _refuse(stage_name, action_name, tok, label):
        try:
            cp.put_approval_result(
                pipelineName=name, stageName=stage_name, actionName=action_name, token=tok,
                result={"summary": f"sim2real {label} probe", "status": "Approved"},
            )
            raise AssertionError(
                f"PutApprovalResult accepted an approval addressed to {stage_name}/{action_name} "
                f"({label}); it must be refused"
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message") or ""

    stage_code, stage_msg = _refuse("Source", "SourceAction", token, "non-approval action")
    assert (stage_code, stage_msg) == (
        _ERR_TOKEN, f"{name} does not include an approval action named SourceAction."
    ), (
        f"an approval addressed to the Source stage's non-approval action must be refused as "
        f"{_ERR_TOKEN} saying the named action is not an APPROVAL action -- the action resolves, "
        f"so the fault is the token's scope -- got {(stage_code, stage_msg)!r}"
    )

    # And the address is resolved outside-in, each level with its own fault: an unknown STAGE
    # never reaches action lookup, and an unknown ACTION inside a real stage never reaches the
    # token check. An emulator with one catch-all approval error fails these two.
    unknown_stage_code, unknown_stage_msg = _refuse(
        "NoSuchStage", "ApproveAction", token, "unknown stage")
    assert (unknown_stage_code, unknown_stage_msg) == (
        _ERR_STAGE,
        f"{name} does not include a stage named NoSuchStage. "
        "Make sure you are using the correct name for the stage, and then try again.",
    ), (
        f"an unknown stage name must be {_ERR_STAGE}, not a token or action fault, got "
        f"{(unknown_stage_code, unknown_stage_msg)!r}"
    )

    unknown_action_code, unknown_action_msg = _refuse(
        "Gate", "NoSuchAction", token, "unknown action")
    assert (unknown_action_code, unknown_action_msg) == (
        _ERR_ACTION,
        "Gate does not include an action named NoSuchAction. "
        "Make sure you are using the correct name for the action, and then try again.",
    ), (
        f"an unknown action inside a real stage must be {_ERR_ACTION} naming the stage it "
        f"searched and the action it could not find, got "
        f"{(unknown_action_code, unknown_action_msg)!r}"
    )

    # None of the three refusals may have advanced the gate.
    parked = _gate_action_state(cp, name).get("latestExecution", {})
    assert parked.get("status") == "InProgress", (
        f"the Gate action advanced to {parked.get('status')!r} after three refused approvals"
    )

    # Control: the correct token advances the execution to a terminal Succeeded.
    cp.put_approval_result(
        pipelineName=name, stageName="Gate", actionName="ApproveAction", token=token,
        result={"summary": "sim2real approved", "status": "Approved"},
    )
    final = _poll(
        lambda: _execution_status(cp, name, execution_id),
        lambda s: s in ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded"),
        timeout_s=run_timeout_s, interval_s=5,
    )
    assert final == "Succeeded", (
        f"after a valid approval, execution {execution_id} must reach the terminal status "
        f"Succeeded, got {final!r}"
    )

    # Replay: the consumed token must not work twice.
    try:
        cp.put_approval_result(
            pipelineName=name, stageName="Gate", actionName="ApproveAction", token=token,
            result={"summary": "sim2real replay", "status": "Approved"},
        )
        raise AssertionError("replaying the consumed approval token succeeded; it must be single-use")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        replay = (err.get("Code"), err.get("Message"))
    assert replay == (
        "ApprovalAlreadyCompletedException",
        "The approval request that you responded to is already complete or has expired. "
        "Review the latest revisions in the pipeline, and then try again.",
    ), (
        f"replaying the consumed approval token returned {replay!r}, expected "
        f"ApprovalAlreadyCompletedException -- the token must be single-use"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
