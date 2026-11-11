"""job-update-and-batch-get."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-update-and-batch-get"
GROUP = 'job'
SERVICES = ['glue']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateJob persists MaxRetries/Timeout; BatchGetJobs partitions found vs. JobsNotFound."""
    glue = ctx.client("glue")
    role_arn = _service_role_arn(ctx)
    job_name = ctx.unique_name("sim2real-behav-glue-job-")
    _retry_iam_propagation(lambda: _create_job(ctx, glue, job_name, role_arn, MaxRetries=0, Timeout=20))

    job = glue.get_job(JobName=job_name)["Job"]
    assert job["MaxRetries"] == 0, f"unexpected initial MaxRetries: {job.get('MaxRetries')}"
    assert job["Timeout"] == 20, f"unexpected initial Timeout: {job.get('Timeout')}"

    glue.update_job(
        JobName=job_name,
        JobUpdate={
            "Role": role_arn,
            "Command": {
                "Name": "glueetl",
                "ScriptLocation": "s3://example-bucket/scripts/job.py",
            },
            "MaxRetries": 2,
            "Timeout": 45,
        },
    )
    updated = glue.get_job(JobName=job_name)["Job"]
    assert updated["MaxRetries"] == 2, f"UpdateJob did not persist MaxRetries: {updated}"
    assert updated["Timeout"] == 45, f"UpdateJob did not persist Timeout: {updated}"

    batch = glue.batch_get_jobs(JobNames=[job_name, "does-not-exist-job"])
    assert [j["Name"] for j in batch["Jobs"]] == [job_name], (
        f"expected only {job_name!r} in Jobs, got {[j['Name'] for j in batch['Jobs']]}"
    )
    assert batch["JobsNotFound"] == ["does-not-exist-job"], (
        f"unknown job must be reported in JobsNotFound: {batch['JobsNotFound']}"
    )

    listed = glue.list_jobs()["JobNames"]
    assert job_name in listed, "job missing from ListJobs"

    glue.delete_job(JobName=job_name)
    expected_message = "Job not found."
    code, message = _error_code(lambda: glue.get_job(JobName=job_name))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after DeleteJob, got {code!r}"
    )
    assert message == expected_message, f"expected GetJob message {expected_message!r}, got {message!r}"

    expected_message = "Job not found."
    code2, message2 = _error_code(
        lambda: glue.update_job(
            JobName=job_name,
            JobUpdate={
                "Role": role_arn,
                "Command": {
                    "Name": "glueetl",
                    "ScriptLocation": "s3://example-bucket/scripts/job.py",
                },
            },
        )
    )
    assert code2 == "EntityNotFoundException", (
        f"expected UpdateJob on a deleted job to raise EntityNotFoundException, got {code2!r}"
    )
    assert message2 == expected_message, f"expected UpdateJob message {expected_message!r}, got {message2!r}"


# ===== helpers =====
_GLUE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "glue.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_GLUE_SERVICE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _quiet(fn):
    """Teardown call: the resource may already be gone; any other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFoundException", "NoSuchEntity"):
            raise


def _service_role_arn(ctx) -> str:
    """Create a real Glue-assumable role and return its ARN.

    Glue rejects cross-account role ARNs and authorizes iam:PassRole before it accepts a job
    definition, so a real in-account role is required for any create path that takes Role.
    IAM is eventually consistent, so wait for the role to be readable; the caller must still
    retry its first use of the role through `_retry_iam_propagation`, since readability of the
    role does not imply PassRole has propagated to Glue's authorization path.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-glue-role-")[:64]
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_GLUE_TRUST_POLICY),
        Description="SimParity behavioral fidelity test role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup():
        _quiet(
            lambda: iam.detach_role_policy(
                RoleName=role_name, PolicyArn=_GLUE_SERVICE_POLICY_ARN
            )
        )
        _quiet(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_GLUE_SERVICE_POLICY_ARN)

    for _ in range(20):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1)
    return arn


def _retry_iam_propagation(fn, timeout_s=60.0, interval_s=5.0):
    """Bounded retry for the first use of a freshly-created role.

    Glue's own PassRole/AssumeRole authorization check lags IAM role readability; retry the
    specific codes that check emits while propagation is still in flight, up to a deadline.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_job(ctx, glue, name, role_arn, **extra) -> None:
    glue.create_job(
        Name=name,
        Role=role_arn,
        Command={
            "Name": "glueetl",
            "ScriptLocation": "s3://example-bucket/scripts/job.py",
        },
        Tags={"sim2real": CHECK},
        **extra,
    )
    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_job(JobName=name)))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
