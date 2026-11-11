"""glue-start-job-run-sync-task-output-carries-the-sdk-envelope."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-start-job-run-sync-task-output-carries-the-sdk-envelope"
GROUP = "task_integrations"
SERVICES = ["glue", "s3", "stepfunctions"]


def _assert_envelope(label: str, out: dict) -> None:
    """The optimized-integration SDK envelope: HTTP status/headers plus a response RequestId."""
    missing = {"SdkHttpMetadata", "SdkResponseMetadata"} - set(out)
    assert not missing, f"{label} output lacks {sorted(missing)!r}: {out!r}"
    http = out["SdkHttpMetadata"]
    assert http.get("HttpStatusCode") == 200, (
        f"{label} SdkHttpMetadata.HttpStatusCode was {http.get('HttpStatusCode')!r}"
    )
    headers = http.get("HttpHeaders")
    assert isinstance(headers, dict) and headers and all(
        isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
    ), f"{label} SdkHttpMetadata.HttpHeaders was {headers!r}, expected a non-empty str->str map"
    all_headers = http.get("AllHttpHeaders")
    assert isinstance(all_headers, dict) and all_headers and all(
        isinstance(k, str) and isinstance(v, list) and all(isinstance(x, str) for x in v)
        for k, v in all_headers.items()
    ), f"{label} SdkHttpMetadata.AllHttpHeaders was {all_headers!r}, expected str->[str] map"
    req_id = out["SdkResponseMetadata"].get("RequestId")
    assert isinstance(req_id, str) and req_id, (
        f"{label} SdkResponseMetadata.RequestId was {req_id!r}"
    )


@tags("axis:happy-path", "cap:c3", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A glue:startJobRun.sync task's TaskSubmitted output — the StartJobRun submission, before
    the .sync poll loop begins — carries the SdkHttpMetadata/SdkResponseMetadata envelope; the
    later TaskSucceeded output is GetJobRun's own run record, with no such envelope.
    """
    glue = ctx.client("glue")

    bucket = _create_bucket(ctx)
    job = _create_job(ctx, bucket)
    role_arn = _create_sfn_role(ctx, job)
    sm_arn = _create_state_machine(ctx, job, role_arn)

    exe = _run_to_terminal(ctx, sm_arn, {})
    assert exe["status"] == "SUCCEEDED", (
        f'execution was {exe["status"]!r}: {exe.get("error")!r} {exe.get("cause")!r}'
    )

    history = _history(ctx, exe["executionArn"])
    submitted = [e["taskSubmittedEventDetails"] for e in history if e["type"] == "TaskSubmitted"]
    assert len(submitted) == 1, f"expected one TaskSubmitted event, got {submitted!r}"
    submit_out = json.loads(submitted[0]["output"])
    _assert_envelope("the glue:startJobRun.sync TaskSubmitted", submit_out)
    run_id = submit_out["JobRunId"]

    succeeded = [e["taskSucceededEventDetails"] for e in history if e["type"] == "TaskSucceeded"]
    assert len(succeeded) == 1, f"expected one TaskSucceeded event, got {succeeded!r}"
    final_out = json.loads(succeeded[0]["output"])
    assert "SdkHttpMetadata" not in final_out and "SdkResponseMetadata" not in final_out, (
        f"the .sync poll's own TaskSucceeded output unexpectedly carries an SDK envelope: "
        f"{final_out!r}"
    )
    assert (final_out["Id"], final_out["JobRunState"]) == (run_id, "SUCCEEDED"), (
        f"the final output names run {final_out.get('Id')!r} in state "
        f"{final_out.get('JobRunState')!r}; the submission named {run_id!r}"
    )

    # Independent read: Glue's own record of the run agrees with both events.
    jr = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
    assert jr["JobRunState"] == "SUCCEEDED", f"Glue reports run {run_id} as {jr['JobRunState']!r}"


# A trivial Python-shell script: no inputs, no outputs, just exits 0.
_SCRIPT = "pass\n"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-gluesfn-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK[:200]}]}
    )
    s3.put_object(Bucket=bucket, Key="script/job.py", Body=_SCRIPT.encode())
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_role(ctx, trust_service, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


def _create_job(ctx, bucket):
    glue = ctx.client("glue")
    job_role = _create_role(ctx, "glue.amazonaws.com", [
        {"Effect": "Allow", "Action": ["s3:GetObject"],
         "Resource": f"arn:aws:s3:::{bucket}/script/*"},
    ])
    name = ctx.unique_name("sim2real-behav-gluejob-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            glue.create_job(
                Name=name,
                Description="sim2real-behav sfn glue .sync envelope job",
                Role=job_role,
                Command={
                    "Name": "pythonshell",
                    "ScriptLocation": f"s3://{bucket}/script/job.py",
                    "PythonVersion": "3.9",
                },
                MaxCapacity=0.0625,
                Timeout=10,
                Tags={"sim2real": CHECK[:200]},
            )
            ctx.on_cleanup(_teardown(lambda: glue.delete_job(JobName=name)))
            return name
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidInputException", "AccessDeniedException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateJob never accepted the fresh job role: {last!r}")


_GLUE_ACTIONS = ("glue:StartJobRun", "glue:GetJobRun", "glue:GetJobRuns", "glue:BatchStopJobRun")


def _create_sfn_role(ctx, job):
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": list(_GLUE_ACTIONS),
         "Resource": f"arn:aws:glue:{ctx.region}:{account_id}:job/{job}"},
    ])


def _create_state_machine(ctx, job, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = {
        "Comment": "sim2real: one glue startJobRun.sync task",
        "StartAt": "Job",
        "States": {
            "Job": {
                "Type": "Task",
                "Resource": "arn:aws:states:::glue:startJobRun.sync",
                "Parameters": {"JobName": job},
                "End": True,
            }
        },
    }
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK[:200]}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(
                lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "security token included in the request is invalid",
    "glue:StartJobRun",
    "AccessDenied",
)


def _start(ctx, sm_arn, payload):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="sim2real-cleanup", cause="cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s=220.0, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _run_to_terminal(ctx, sm_arn, payload, *, propagation_s=90.0):
    retry_until = time.monotonic() + propagation_s
    while True:
        exec_arn = _start(ctx, sm_arn, payload)
        desc = _wait_terminal(ctx, exec_arn)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        if time.monotonic() >= retry_until:
            return desc
        time.sleep(2)


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 200}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
