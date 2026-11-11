"""job-batch-stop-run."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-batch-stop-run"
GROUP = 'job'
SERVICES = ['glue']

def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _glue_role_arn(ctx):
    """Create a dedicated, self-cleaning Glue-assumable IAM role and return its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="SimParity behavioral fidelity check role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]

def _create_job(ctx, glue, role):
    """Create a pythonshell job (cheapest run profile); track for cleanup."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    glue.create_job(
        Name=name,
        Role=role,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
        MaxCapacity=0.0625,
        Timeout=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name


def _retry_role_propagation(fn, timeout_s=90.0, interval_s=5.0):
    """IAM role/policy propagation is eventually consistent; Glue's AssumeRole probe on
    start_job_run can reject a freshly-created role with AccessDenied(Exception) until the
    role/policy attachment propagates. Retry until timeout_s, then let the terminal error surface."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for terminal state, last={last!r}")


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """batch_stop_job_run reports per-run success/error entries rather than a single pass/fail,
    and the disposition it reports must be confirmed by an independent read (get_job_run) rather
    than trusted on batch_stop_job_run's own say-so."""
    from botocore.exceptions import ClientError

    glue = ctx.client("glue")
    name = _create_job(ctx, glue, _glue_role_arn(ctx))

    started = _retry_role_propagation(lambda: glue.start_job_run(JobName=name))
    run_id = started["JobRunId"]

    resp = glue.batch_stop_job_run(JobName=name, JobRunIds=[run_id, "nonexistent-run-id"])

    successful_ids = {r["JobRunId"] for r in resp.get("SuccessfulSubmissions", [])}
    errored = resp.get("Errors", [])
    errored_ids = {e["JobRunId"] for e in errored}

    # The bogus run id must be reported as an error, not silently accepted.
    assert "nonexistent-run-id" in errored_ids, f"expected nonexistent-run-id in errors, got {errored}"
    # The real run must either have been stopped or reported as already-terminal;
    # either way it must appear in exactly one of the two buckets, never neither.
    assert run_id in successful_ids or run_id in errored_ids, (
        f"run {run_id} missing from both SuccessfulSubmissions and Errors: {resp}"
    )

    # Independent read at the destination, through a different operation than the one
    # that mutated (get_job_run, not batch_stop_job_run): the nonexistent id must genuinely
    # not resolve, not merely be reported as an error by the call we are grading.
    expected_message = "Job run not found for the given job name and runId."
    try:
        glue.get_job_run(JobName=name, RunId="nonexistent-run-id")
        raise AssertionError("get_job_run resolved a run id batch_stop_job_run had just rejected as nonexistent")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        message = e.response.get("Error", {}).get("Message")
        assert code == "EntityNotFoundException", (
            f"expected EntityNotFoundException reading back the nonexistent run id, got {code}"
        )
        assert message == expected_message, (
            f"expected message {expected_message!r} reading back the nonexistent run id, got {message!r}"
        )

    # And the real run's disposition must be corroborated by get_job_run's own state, not
    # just by which bucket batch_stop_job_run put it in.
    terminal_states = {"STOPPED", "STOPPING", "SUCCEEDED", "FAILED", "TIMEOUT", "ERROR"}
    final_state = _poll_until(
        lambda: glue.get_job_run(JobName=name, RunId=run_id)["JobRun"]["JobRunState"],
        lambda s: s in terminal_states,
    )
    if run_id in successful_ids:
        assert final_state in {"STOPPED", "STOPPING"}, (
            f"batch_stop_job_run accepted the stop request for {run_id}, but the independent "
            f"get_job_run read reports state={final_state!r}, not stopping/stopped"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
