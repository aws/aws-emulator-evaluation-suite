"""glue-job-max-retries-two-produces-three-attempts-chained-by-previous-run-id."""
# A job with MaxRetries=2 whose script exits non-zero produces three job runs: the original plus
# two retries ("The maximum number of times to retry this job after a JobRun fails",
# https://docs.aws.amazon.com/glue/latest/webapi/API_Job.html). The runs carry consecutive Attempt
# values starting at 0, each retry's PreviousRunId names its predecessor, and all three end
# FAILED. The absence of a retry on the MaxRetries=0 control is bounded by the subject's own
# measured retry latency, not by a sleep. A fresh IAM role is not immediately assumable by Glue,
# so its early "assume role permissions" failures are spent on the control job, where they cannot
# reach the subject's retry chain. Every terminal JobRun carries StartedOn and CompletedOn.
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "glue-job-max-retries-two-produces-three-attempts-chained-by-previous-run-id"
GROUP = "job"
SERVICES = ["glue", "s3"]

_MAX_RETRIES = 2
# Exits non-zero every time, on every attempt, with no dependence on anything outside the run.
_SCRIPT = b"import sys\nprint('sim2real deliberate failure', flush=True)\nsys.exit(1)\n"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:e2e", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """MaxRetries=2 yields three FAILED runs chained by PreviousRunId; MaxRetries=0 yields one."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluertry-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="scripts/fail.py", Body=_SCRIPT)

    role_arn = _create_glue_role(ctx, iam, bucket)

    control = _create_failing_job(ctx, glue, bucket, role_arn, "ctl", max_retries=0)
    subject = _create_failing_job(ctx, glue, bucket, role_arn, "sub",
                                  max_retries=_MAX_RETRIES)

    # The two jobs really do differ in exactly one setting, read back through GetJob rather
    # than trusted from CreateJob's own response.
    assert glue.get_job(JobName=control)["Job"]["MaxRetries"] == 0, (
        f"control job {control} reports MaxRetries="
        f"{glue.get_job(JobName=control)['Job'].get('MaxRetries')!r}, expected 0"
    )
    assert glue.get_job(JobName=subject)["Job"]["MaxRetries"] == _MAX_RETRIES, (
        f"subject job {subject} reports MaxRetries="
        f"{glue.get_job(JobName=subject)['Job'].get('MaxRetries')!r}, expected {_MAX_RETRIES}"
    )

    # --- control leg, which also burns off IAM propagation -------------------------------
    # Runs the MaxRetries=0 job until one attempt fails for the SCRIPT's reason rather than
    # for an unpropagated role. That run's id is the control: nothing may ever name it as a
    # PreviousRunId.
    control_run = _run_until_script_failure(glue, control)
    control_id = control_run["Id"]
    control_completed = time.monotonic()
    assert control_run["Attempt"] == 0, (
        f"the control run {control_id} reports Attempt={control_run['Attempt']!r}; the first "
        f"attempt of a run must be 0 for the chain arithmetic below to hold"
    )

    # --- subject leg ---------------------------------------------------------------------
    origin_id = glue.start_job_run(JobName=subject)["JobRunId"]

    expected_total = _MAX_RETRIES + 1

    def _terminal_chain() -> list:
        runs = _job_runs(glue, subject)
        if len(runs) < expected_total:
            return []
        if any(r["JobRunState"] not in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT")
               for r in runs):
            return []
        return runs

    chain = _poll_until(
        _terminal_chain,
        lambda runs: bool(runs),
        timeout_s=1200.0,
        interval_s=10.0,
        reason=(f"MaxRetries={_MAX_RETRIES} must produce {expected_total} runs; Glue schedules "
                f"each retry only after the previous attempt reaches a terminal state, and the "
                f"backoff between attempts is unmeasured (H5)"),
    )

    # THE assertion an emulator with no retry machinery fails: it produces exactly one run.
    assert len(chain) == expected_total, (
        f"GetJobRuns({subject}) reported {len(chain)} runs, expected {expected_total} for "
        f"MaxRetries={_MAX_RETRIES}: one original plus two retries. Ids/attempts/states: "
        f"{[(r['Id'], r.get('Attempt'), r.get('JobRunState')) for r in chain]!r}"
    )
    states = sorted(r["JobRunState"] for r in chain)
    assert states == ["FAILED"] * expected_total, (
        f"the {expected_total} runs of {subject} ended {states!r}; the script exits non-zero "
        f"every time, so every attempt including both retries must be FAILED"
    )

    by_attempt = {r["Attempt"]: r for r in chain}
    assert sorted(by_attempt) == list(range(expected_total)), (
        f"the runs carry Attempt values {sorted(by_attempt)}, expected the consecutive range "
        f"{list(range(expected_total))}: MaxRetries={_MAX_RETRIES} means attempts 0, 1 and 2, "
        f"not repeated or sparse counters"
    )
    assert by_attempt[0]["Id"] == origin_id, (
        f"the Attempt=0 run is {by_attempt[0]['Id']!r} but StartJobRun returned "
        f"{origin_id!r}; the original attempt must be the run the check started"
    )
    assert "PreviousRunId" not in by_attempt[0], (
        f"the original run {origin_id} carries PreviousRunId="
        f"{by_attempt[0].get('PreviousRunId')!r}; it retried nothing"
    )

    # The chain is a chain: each retry names its immediate predecessor. The expected value at
    # every step is an id the TARGET reported, so no recording can carry it.
    for attempt in range(1, expected_total):
        retry = by_attempt[attempt]
        predecessor = by_attempt[attempt - 1]["Id"]
        assert retry["PreviousRunId"] == predecessor, (
            f"the Attempt={attempt} run {retry['Id']!r} reports PreviousRunId="
            f"{retry.get('PreviousRunId')!r}, expected {predecessor!r} — the id of the "
            f"Attempt={attempt - 1} run. Retries must form one chain, not point at the "
            f"original or at nothing"
        )

    # An independent read at a different operation than the list: GetJobRun on the last retry
    # by id must agree, so the chain is not an artefact of GetJobRuns' projection.
    last = by_attempt[expected_total - 1]
    reread = glue.get_job_run(JobName=subject, RunId=last["Id"])["JobRun"]
    assert reread["Attempt"] == last["Attempt"], (
        f"GetJobRun({last['Id']}) reports Attempt={reread.get('Attempt')!r} but GetJobRuns "
        f"reported {last['Attempt']!r}"
    )
    assert reread["PreviousRunId"] == by_attempt[expected_total - 2]["Id"], (
        f"GetJobRun({last['Id']}) reports PreviousRunId={reread.get('PreviousRunId')!r}, "
        f"expected {by_attempt[expected_total - 2]['Id']!r}"
    )

    # --- the control's absence, bounded by the subject's OWN measured latency --------
    # L is the retry SCHEDULING latency measured on this target in this run: the longest gap
    # between an attempt reaching a terminal state and its retry starting. The control
    # terminated before the subject even started, so its window is usually already the whole
    # subject chain; any shortfall to 3L is polled out, so a correct-but-slow target cannot be
    # scored as having suppressed the retry.
    gaps = []
    for attempt in range(1, expected_total):
        finished = by_attempt[attempt - 1]["CompletedOn"]
        started = by_attempt[attempt]["StartedOn"]
        gaps.append((started - finished).total_seconds())
    latency = max(gaps)
    assert latency >= 0, (
        f"the measured retry gaps were {gaps!r}; a retry cannot start before the attempt it "
        f"retries has completed, so the run records are inconsistent"
    )
    control_runs = _job_runs(glue, control)
    window_end = control_completed + 3 * latency
    left = ctx.time_left()
    if left is not None and window_end - time.monotonic() > left:
        raise AssertionError(
            f"the 3L={3 * latency:.0f}s absence window (gaps {gaps!r}) does not fit the "
            f"{left:.0f}s left in the run; a shorter window would let a correct-but-slow target "
            f"read as having suppressed the retry"
        )
    while time.monotonic() < window_end and not any(
            r.get("PreviousRunId") == control_id for r in control_runs):
        time.sleep(2.0)
        control_runs = _job_runs(glue, control)
    window = time.monotonic() - control_completed
    retries_of_control = [r["Id"] for r in control_runs
                          if r.get("PreviousRunId") == control_id]
    assert not retries_of_control, (
        f"the MaxRetries=0 control run {control_id!r} was retried by {retries_of_control!r} "
        f"after a {window:.0f}s window; MaxRetries=0 must mean no retry, and without this leg "
        f"a target that retries everything unconditionally would pass"
    )
    assert all(r["Attempt"] == 0 for r in control_runs), (
        f"the control job's runs carry Attempt values "
        f"{[(r['Id'], r['Attempt']) for r in control_runs]!r}; with MaxRetries=0 every run is "
        f"a first attempt"
    )


# ===== helpers =====

def _create_failing_job(ctx, glue, bucket: str, role_arn: str, label: str, *,
                        max_retries: int) -> str:
    job = ctx.unique_name(f"sim2real-behav-gluertry-{label}-")
    glue.create_job(
        Name=job,
        Role=role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9",
                 "ScriptLocation": f"s3://{bucket}/scripts/fail.py"},
        MaxCapacity=0.0625,
        GlueVersion="3.0",
        MaxRetries=max_retries,
        # Minutes. Bounds a hung attempt so it cannot silently consume the whole budget.
        Timeout=10,
        # A retried run races Glue's concurrency accounting, which lags the previous run's own
        # terminal state; MaxConcurrentRuns=1 would make the retries fail outright.
        ExecutionProperty={"MaxConcurrentRuns": 5},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_job(JobName=job),
                                         f"glue job {job}"))
    return job


def _run_until_script_failure(glue, job: str, *, timeout_s: float = 600.0) -> dict:
    """Start `job` until an attempt fails for the SCRIPT's reason rather than because the fresh
    IAM role is not yet assumable by Glue. Glue reports that as a FAILED job RUN about 5s in,
    not as a StartJobRun error, and no API reports that a role has become assumable — so the
    bounded retry has to be on the terminal run state. Raises on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            run_id = glue.start_job_run(JobName=job)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException":
                raise
            time.sleep(5)
            continue
        while time.monotonic() < deadline:
            last = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
            if last["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR", "TIMEOUT"):
                break
            time.sleep(5)
        if last.get("JobRunState") != "FAILED":
            raise AssertionError(
                f"warm-up run {run_id} of {job} ended {last.get('JobRunState')!r}; the script "
                f"exits non-zero, so every attempt must be FAILED: {last!r}"
            )
        if "assume role permissions" not in (last.get("ErrorMessage") or ""):
            return last
        time.sleep(2)
    raise AssertionError(
        f"no run of {job} failed for the script's own reason within {timeout_s}s; the last "
        f"attempt reported {last.get('ErrorMessage')!r}"
    )


def _job_runs(glue, job: str) -> list:
    runs = []
    for page in glue.get_paginator("get_job_runs").paginate(JobName=job):
        runs.extend(page["JobRuns"])
    return runs


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, reason: str):
    """Bounded retry that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never satisfied within {timeout_s}s ({reason}); "
                f"last value={last!r}"
            )
        time.sleep(interval_s)


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str) -> str:
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    role = ctx.unique_name("sim2real-behav-gluerole-")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    # Registered first so it runs last: DeleteRole refuses while any policy is still attached.
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow", "Action": ["s3:ListBucket"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    return arn


def _retry_delete(fn, label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions: a
    throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
