"""stop-pipeline-execution-terminal-not-stoppable."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-pipeline-execution-terminal-not-stoppable"
GROUP = 'error-semantics'
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


def _purge_bucket(s3, bucket) -> None:
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
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=bucket, Key="source.zip", Body=_source_zip())
    return bucket


def _assumable_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cprole-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
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
    return role_arn


def _declaration(name, role_arn, bucket):
    """Source(S3) -> Approval(Manual), executionMode QUEUED so a second execution is its own
    execution rather than superseding the first. A manual-approval stage holds the execution in
    a real non-terminal state at zero cost and provisions nothing downstream."""
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
            return cp.create_pipeline(pipeline=declaration)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _gate_awaiting(cp, name):
    for stage in cp.get_pipeline_state(name=name).get("stageStates", []):
        if stage.get("stageName") == "Gate":
            latest = stage.get("latestExecution", {})
            if latest.get("status") == "InProgress":
                return latest.get("pipelineExecutionId")
    return None


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


def _not_stoppable_message(name, execution_id):
    return (
        f"The pipeline execution with ID '{execution_id}' in '{name}' can't be stopped now. Either "
        "it does not exist in the pipeline, or the pipeline execution has no action executions in "
        "progress."
    )


def _error(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError fn raises; fail loudly if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _stop(cp, name, execution_id):
    return cp.stop_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
        reason="sim2real stop probe",
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopPipelineExecution with abandon drives an execution to Stopped; stopping it again or stopping an
    unknown id fails with PipelineExecutionNotStoppableException, an unknown pipeline with
    PipelineNotFoundException, and a new execution still starts.
    """

    cp = ctx.client("codepipeline")
    bucket = _artifact_store(ctx)
    role_arn = _assumable_role(ctx, bucket)
    create_timeout_s = 180
    run_timeout_s = 420

    name = ctx.unique_name("sim2real-behav-cpstop-")
    _create_with_role_propagation(cp, _declaration(name, role_arn, bucket),
                                  timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    # Creating a pipeline with a source action starts an execution; wait for it to park at the
    # approval gate, which is a genuine, observable non-terminal state.
    first_id = _poll(lambda: _gate_awaiting(cp, name), lambda i: bool(i),
                     timeout_s=run_timeout_s, interval_s=5)
    assert first_id, (
        "no execution reached the Gate approval stage; an emulator that does not advance an "
        "execution out of the Source stage fails here"
    )
    ctx.on_cleanup(lambda: _abandon(cp, name, first_id))
    assert _execution_status(cp, name, first_id) == "InProgress", (
        f"execution {first_id} parked at an approval gate must report InProgress, got "
        f"{_execution_status(cp, name, first_id)!r}"
    )

    # The stop itself must succeed and drive the execution to Stopped, not Failed.
    stop_resp = _stop(cp, name, first_id)
    assert stop_resp["pipelineExecutionId"] == first_id, (
        f"StopPipelineExecution must echo the stopped execution {first_id}, got {stop_resp!r}"
    )
    stopped = _poll(
        lambda: _execution_status(cp, name, first_id),
        lambda s: s in ("Stopped", "Succeeded", "Failed", "Cancelled", "Superseded"),
        timeout_s=run_timeout_s, interval_s=5,
    )
    assert stopped == "Stopped", (
        f"an abandoned execution must reach the terminal status Stopped, got {stopped!r}"
    )

    # Break exactly one thing: stop an execution that is already terminal.
    code, message = _error(lambda: _stop(cp, name, first_id))
    assert code == "PipelineExecutionNotStoppableException", (
        f"StopPipelineExecution misclassified a stop of the already-Stopped "
        f"execution {first_id}: error code was {code!r}, expected "
        f"PipelineExecutionNotStoppableException"
    )
    expected = _not_stoppable_message(name, first_id)
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the refused stop must not have rewritten the terminal status.
    assert _execution_status(cp, name, first_id) == "Stopped", (
        f"the terminal status of execution {first_id} changed after a refused stop: "
        f"{_execution_status(cp, name, first_id)!r}"
    )

    # A never-issued execution id is refused with PipelineExecutionNotStoppableException, which does
    # not distinguish absent from not stoppable; GetPipelineExecution proves the id is absent by
    # answering PipelineExecutionNotFoundException for it.
    unknown = "11111111-2222-3333-4444-555555555555"
    code, message = _error(lambda: _stop(cp, name, unknown))
    assert code == "PipelineExecutionNotStoppableException", (
        f"StopPipelineExecution misclassified an execution id that does not "
        f"exist: error code was {code!r}, expected PipelineExecutionNotStoppableException -- "
        f"the same code an already-terminal execution gets"
    )
    expected = _not_stoppable_message(name, unknown)
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    get_code, get_message = _error(
        lambda: cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=unknown)
    )
    assert get_code == "PipelineExecutionNotFoundException", (
        f"GetPipelineExecution must report the unknown id {unknown} as "
        f"PipelineExecutionNotFoundException, which is what proves it was never issued and that "
        f"the NotStoppable answer above really is a conflation; got {get_code!r}"
    )
    expected = f"Pipeline Execution with id '{unknown}' does not exist in pipeline with name '{name}'"
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"

    # An unknown PIPELINE, by contrast, is not conflated at all.
    absent_pipeline = f"{name}-absent"
    code, message = _error(lambda: _stop(cp, absent_pipeline, first_id))
    assert code == "PipelineNotFoundException", (
        f"StopPipelineExecution against a pipeline that does not exist must be "
        f"PipelineNotFoundException, not the execution-level NotStoppable fault, got {code!r}"
    )
    account = role_arn.split(":")[4]
    expected = f"Pipeline with name {absent_pipeline} does not exist in account {account}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Control: the pipeline still works -- a new execution starts and reaches the gate.
    second_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    ctx.on_cleanup(lambda: _abandon(cp, name, second_id))
    arrived = _poll(lambda: _gate_awaiting(cp, name), lambda i: i == second_id,
                    timeout_s=run_timeout_s, interval_s=5)
    assert arrived == second_id, (
        f"after the stops, a new execution must still reach the Gate stage; the stage reports "
        f"{arrived!r} for expected {second_id!r}"
    )
    assert _execution_status(cp, name, second_id) == "InProgress", (
        f"the control execution {second_id} must be InProgress at the gate, got "
        f"{_execution_status(cp, name, second_id)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
