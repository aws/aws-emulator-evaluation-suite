"""xsvc-sfn-1-glue-sync-without-get-job-run-is-denied-and-times-out."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-1-glue-sync-without-get-job-run-is-denied-and-times-out"
GROUP = 'sync_integration'
SERVICES = ['glue', 's3', 'stepfunctions']

_MANAGED_TAG_KEY = "sim2real:managed"
_TAG_PREFIX = "sim2real-xsvc"


# Long enough for the positive control (one ~60 s .sync poll after a ~20 s run), short
# enough to stay well inside a 300 s check budget.
_TASK_TIMEOUT_S = 150


# timing:real-time — workflow: 150 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags("axis:rejection", "concern:negative-classes", "concern:e2e", "dp:api", "plane:data", "cap:c3", "timing:real-time")
def run(ctx) -> None:
    """A glue:startJobRun.sync task whose role lacks glue:GetJobRun ends the execution FAILED with
    States.Timeout (TaskTimedOut, no TaskFailed) while its job run SUCCEEDED and wrote its
    marker; with GetJobRun the same machine SUCCEEDS.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    job = _create_job(ctx, bucket)
    full_role = _create_sfn_role(ctx, account_id, job)
    blind_role = _create_sfn_role(
        ctx, account_id, job,
        glue_actions=tuple(a for a in _GLUE_ACTIONS if a != "glue:GetJobRun"),
    )
    full_sm = _create_state_machine(ctx, job, bucket, full_role, timeout_seconds=_TASK_TIMEOUT_S)
    blind_sm = _create_state_machine(ctx, job, bucket, blind_role, timeout_seconds=_TASK_TIMEOUT_S)

    # Start both side by side so the check costs one timeout, not a timeout plus a run.
    good_token, bad_token = ctx.unique_name("tok-"), ctx.unique_name("tok-")
    good_key, bad_key = f"out/{good_token}.txt", f"out/{bad_token}.txt"
    good_payload = {"mode": "ok", "key": good_key, "token": good_token}
    bad_payload = {"mode": "ok", "key": bad_key, "token": bad_token}
    good_arn, bad_arn = _start(ctx, full_sm, good_payload), _start(ctx, blind_sm, bad_payload)

    bad = _wait_terminal(ctx, bad_arn, timeout_s=_TASK_TIMEOUT_S + 90.0)
    for _ in range(3):
        if not _is_propagation_failure(bad):
            break
        time.sleep(5)
        bad = _wait_terminal(ctx, _start(ctx, blind_sm, bad_payload),
                             timeout_s=_TASK_TIMEOUT_S + 90.0)
    good = _wait_terminal(ctx, good_arn, timeout_s=60.0)
    if _is_propagation_failure(good):
        good = _run_to_terminal(ctx, full_sm, good_payload)

    assert good["status"] == "SUCCEEDED", (
        f'the positive control was {good["status"]!r}: {good.get("error")!r} '
        f'{good.get("cause")!r}'
    )
    good_body = s3.get_object(Bucket=bucket, Key=good_key)["Body"].read().decode()
    assert good_body == f"sim2real-ok:{good_token}", f"the control's job wrote {good_body!r}"

    # A State-level TimeoutSeconds fails the execution (status FAILED, error States.Timeout);
    # TIMED_OUT is reserved for the execution-level TimeoutSeconds, which is not set here.
    assert bad["status"] == "FAILED", (
        f'a role without glue:GetJobRun ended {bad["status"]!r} '
        f'({bad.get("error")!r} {bad.get("cause")!r}), expected FAILED'
    )
    assert bad.get("error") == "States.Timeout", (
        f'the execution timed out with error {bad.get("error")!r}, expected States.Timeout'
    )
    history = _history(ctx, bad["executionArn"])
    types = [e["type"] for e in history]
    assert "TaskSubmitted" in types and "TaskTimedOut" in types, (
        f"the run must have been submitted and the task timed out: {types!r}"
    )
    assert "TaskSucceeded" not in types and "TaskFailed" not in types, (
        f"the denied poll must neither succeed nor fail the task: {types!r}"
    )

    # The run really ran to completion: the denial is on observing it, not on running it.
    run_id = _submitted_run_id(ctx, bad["executionArn"])
    jr = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
    assert jr["JobRunState"] == "SUCCEEDED", (
        f"Glue reports the blind role's run {run_id} as {jr['JobRunState']!r}"
    )
    bad_body = s3.get_object(Bucket=bucket, Key=bad_key)["Body"].read().decode()
    assert bad_body == f"sim2real-ok:{bad_token}", f"the blind role's job wrote {bad_body!r}"


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
    """A Python-shell job whose role can read its script and write markers, and nothing else.

    The job role deliberately has no CloudWatch Logs grant, so a run leaves no log stream in
    the account's shared /aws-glue log groups behind it.
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
    # IAM propagation exposes no condition to poll. The bounded AccessDeniedException retry in
    # _create_state_machine and the propagation retry in _run_to_terminal are what absorb it.
    time.sleep(8)
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


def _run_to_terminal(ctx, sm_arn, payload, *, timeout_s=220.0, max_attempts=4):
    """Start an execution and poll to terminal, absorbing IAM propagation at first use only.

    The first StartJobRun is the first runtime use of the fresh role, so a failure whose cause
    names the role assumption or that start call is the propagation race; every retry is a
    fresh execution, never a sleep standing in for the wait.
    """
    desc = None
    for _ in range(max_attempts):
        desc = _wait_terminal(ctx, _start(ctx, sm_arn, payload), timeout_s=timeout_s)
        if not _is_propagation_failure(desc):
            return desc
        time.sleep(5)
    return desc


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
