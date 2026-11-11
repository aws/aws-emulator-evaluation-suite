"""xsvc-sfn-1-glue-sync-stop-execution-stops-the-running-job-run."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-1-glue-sync-stop-execution-stops-the-running-job-run"
GROUP = 'sync_integration'
SERVICES = ['glue', 's3', 'stepfunctions']

_MANAGED_TAG_KEY = "sim2real:managed"
_TAG_PREFIX = "sim2real-xsvc"


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """StopExecution during a glue:startJobRun.sync wait stops the Glue job run itself.

    The run, read from Glue, ends STOPPED without writing its marker; the execution is ABORTED.
    """
    glue = ctx.client("glue")
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    job = _create_job(ctx, bucket)
    role_arn = _create_sfn_role(ctx, account_id, job)
    sm_arn = _create_state_machine(ctx, job, bucket, role_arn)

    token = ctx.unique_name("tok-")
    key = f"out/{token}.txt"
    exec_arn, run_id = _start_until_submitted(
        ctx, sm_arn, {"mode": "sleep", "key": key, "token": token}
    )
    ctx.on_cleanup(lambda: _best_effort_stop_run(ctx, job, run_id))

    state = _wait_run_state(ctx, job, run_id, {"RUNNING"}, timeout_s=120.0)
    assert state == "RUNNING", f"run {run_id} never reached RUNNING, last state {state!r}"
    before = sfn.describe_execution(executionArn=exec_arn)
    assert before["status"] == "RUNNING", (
        f"the execution was {before['status']!r} while its job run was still RUNNING"
    )

    sfn.stop_execution(executionArn=exec_arn, error="sim2real.Stop", cause="stop while parked")

    final = _wait_run_state(
        ctx, job, run_id, {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}, timeout_s=150.0
    )
    assert final == "STOPPED", (
        f"after StopExecution the Glue run ended {final!r}, expected STOPPED: stopping a .sync "
        f"execution must stop the downstream job run"
    )
    assert not _key_exists(ctx, bucket, key), (
        f"the stopped run must not have written s3://{bucket}/{key}"
    )

    exe = sfn.describe_execution(executionArn=exec_arn)
    assert exe["status"] == "ABORTED", f"the stopped execution is {exe['status']!r}"
    assert (exe.get("error"), exe.get("cause")) == ("sim2real.Stop", "stop while parked"), (
        f"the aborted execution carries {exe.get('error')!r} / {exe.get('cause')!r}"
    )
    types = [e["type"] for e in _history(ctx, exec_arn)]
    assert types[-1] == "ExecutionAborted", f"the history ends with {types[-1]!r}: {types!r}"
    assert "TaskSucceeded" not in types and "TaskFailed" not in types, (
        f"a task stopped mid-wait must neither succeed nor fail: {types!r}"
    )


def _start_until_submitted(ctx, sm_arn, payload, *, propagation_s=90.0, timeout_s=60.0):
    """Start, and return once the task has submitted its job run (TaskSubmitted).

    A failure before submission whose cause names the role or StartJobRun is the IAM
    propagation race on a fresh role; anything else is a real defect and fails here.
    """
    sfn = ctx.client("stepfunctions")
    last = None
    retry_until = time.monotonic() + _capped(ctx, propagation_s)
    while True:
        exec_arn = _start(ctx, sm_arn, payload)
        deadline = time.monotonic() + _capped(ctx, timeout_s)
        while time.monotonic() < deadline:
            run_id = _submitted_run_id(ctx, exec_arn)
            if run_id:
                return exec_arn, run_id
            last = sfn.describe_execution(executionArn=exec_arn)
            if last["status"] != "RUNNING":
                break
            time.sleep(2)
        if last is None or not _is_propagation_failure(last):
            raise AssertionError(f"the task never submitted its job run: {last!r}")
        if time.monotonic() >= retry_until:
            raise AssertionError(f"the role never became usable within {propagation_s:.0f}s: {last!r}")
        time.sleep(2)


def _wait_run_state(ctx, job, run_id, wanted, *, timeout_s, interval_s=2.0):
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]["JobRunState"]
        if state in wanted:
            return state
        time.sleep(interval_s)
    return state


def _best_effort_stop_run(ctx, job, run_id):
    """An already-terminal run comes back in the response's Errors, not as an exception."""
    try:
        ctx.client("glue").batch_stop_job_run(JobName=job, JobRunIds=[run_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


# A Python-shell job script driven by its arguments: "ok" writes a marker object, "fail"
# raises with a caller-chosen message, "sleep" runs long enough to be stopped mid-flight.
_SCRIPT = '''import sys, time, boto3
a = sys.argv
def v(k):
    return a[a.index("--" + k) + 1]
mode = v("mode")
if mode == "fail":
    raise RuntimeError(v("why"))
if mode == "sleep":
    time.sleep(600)
boto3.client("s3", region_name=v("region")).put_object(
    Bucket=v("bucket"), Key=v("key"), Body=("sim2real-ok:" + v("token")).encode())
'''


def _resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _TAG_PREFIX}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _tags_lower():
    return [{"key": k, "value": v} for k, v in _resource_tags().items()]


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-xsvc-gluesfn-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})
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


def _key_exists(ctx, bucket, key):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=key):
        if any(o["Key"] == key for o in page.get("Contents", [])):
            return True
    return False


def _create_role(ctx, prefix, service, statements, description):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": service},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Description=description,
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=f"{role_name}-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_arn


def _create_job(ctx, bucket):
    """A Python-shell job whose role can only read its script and write markers.

    No CloudWatch Logs grant, so a run leaves no stream in the shared /aws-glue log groups.
    """
    glue = ctx.client("glue")
    job_role = _create_role(
        ctx, "sim2real-xsvc-gluejob-", "glue.amazonaws.com",
        [
            {"Effect": "Allow", "Action": ["s3:GetObject"],
             "Resource": f"arn:aws:s3:::{bucket}/script/*"},
            {"Effect": "Allow", "Action": ["s3:PutObject"],
             "Resource": f"arn:aws:s3:::{bucket}/out/*"},
        ],
        "sim2real-xsvc glue python-shell job role",
    )
    name = ctx.unique_name("sim2real-xsvc-gluejob-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            glue.create_job(
                Name=name,
                Description="sim2real-xsvc sfn glue .sync job",
                Role=job_role,
                Command={
                    "Name": "pythonshell",
                    "ScriptLocation": f"s3://{bucket}/script/job.py",
                    "PythonVersion": "3.9",
                },
                MaxCapacity=0.0625,
                ExecutionProperty={"MaxConcurrentRuns": 4},
                Timeout=15,
                Tags=_resource_tags(),
            )
            ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
            return name
        except ClientError as exc:
            # CreateJob validates that Glue can assume the fresh role: IAM propagation.
            if exc.response["Error"]["Code"] not in ("InvalidInputException", "AccessDeniedException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateJob never accepted the fresh job role: {last!r}")


_GLUE_ACTIONS = (
    "glue:StartJobRun",
    "glue:GetJobRun",
    "glue:GetJobRuns",
    "glue:BatchStopJobRun",
)


def _create_sfn_role(ctx, account_id, job, *, glue_actions=_GLUE_ACTIONS):
    role_arn = _create_role(
        ctx, "sim2real-xsvc-gluesfn-", "states.amazonaws.com",
        [{"Effect": "Allow", "Action": list(glue_actions),
          "Resource": f"arn:aws:glue:{ctx.region}:{account_id}:job/{job}"}],
        "sim2real-xsvc sfn glue .sync execution role",
    )
    # IAM propagation is absorbed at first use: the AccessDeniedException retry in
    # _create_state_machine and the deadline-bound propagation retry in _start_until_submitted.
    return role_arn


def _create_state_machine(ctx, job, bucket, role_arn, *, timeout_seconds=None):
    sfn = ctx.client("stepfunctions")
    task = {
        "Type": "Task",
        "Resource": "arn:aws:states:::glue:startJobRun.sync",
        "Parameters": {
            "JobName": job,
            "Arguments": {
                "--mode.$": "$.mode",
                "--key.$": "$.key",
                "--token.$": "$.token",
                "--why": "sim2real-glue-intentional-failure",
                "--bucket": bucket,
                "--region": ctx.region,
            },
        },
        "End": True,
    }
    if timeout_seconds is not None:
        task["TimeoutSeconds"] = timeout_seconds
    definition = {
        "Comment": "sim2real-xsvc: one glue startJobRun.sync task",
        "StartAt": "Job",
        "States": {"Job": task},
    }
    name = ctx.unique_name("sim2real-xsvc-gluesm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=_tags_lower(),
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "UnrecognizedClientException",
    "glue:StartJobRun",
    "Access Denied",
    "AccessDenied",
)


def _capped(ctx, budget_s):
    """The wait bound, capped by the run's remaining time so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, left)


def _start(ctx, sm_arn, payload):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-xsvc-exec-"),
        input=json.dumps(payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _is_propagation_failure(desc):
    blob = (desc.get("cause") or "") + (desc.get("error") or "")
    return desc["status"] == "FAILED" and any(m in blob for m in _PROPAGATION_MARKERS)


def _run_to_terminal(ctx, sm_arn, payload, *, timeout_s=220.0, propagation_s=90.0):
    """Start an execution and poll to terminal, retrying a fresh execution on IAM propagation.

    The first StartJobRun is the fresh role's first use, so a cause naming it is the race.
    """
    retry_until = time.monotonic() + _capped(ctx, propagation_s)
    while True:
        desc = _wait_terminal(ctx, _start(ctx, sm_arn, payload), timeout_s=timeout_s)
        if not _is_propagation_failure(desc) or time.monotonic() >= retry_until:
            return desc
        time.sleep(2)


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


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


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


def _submitted_run_id(ctx, exec_arn):
    for e in _history(ctx, exec_arn):
        if e["type"] == "TaskSubmitted":
            return json.loads(e["taskSubmittedEventDetails"]["output"])["JobRunId"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
