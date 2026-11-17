"""get-dashboard-url-rejects-job-resource-type."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-dashboard-url-rejects-job-resource-type"
GROUP = "observability"
SERVICES = ["glue", "iam"]


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDashboardUrl rejects ResourceType JOB with OperationNotSupportedException,
    for a real job exactly as it does for a job name that was never created.
    """
    glue = ctx.client("glue")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-dash-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    created_role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    role_arn = created_role["Role"]["Arn"]

    job_name = ctx.unique_name("sim2real-behav-dash-job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={"Name": "glueetl", "ScriptLocation": f"s3://sim2real-behav-dash/{job_name}.py"},
        GlueVersion="4.0",
    )
    ctx.on_cleanup(_teardown(lambda: glue.delete_job(JobName=job_name), "EntityNotFoundException"))

    expected = ("OperationNotSupportedException", "GetDashboardUrl operation is not supported for JOB")

    code_real, msg_real = _error(lambda: glue.get_dashboard_url(ResourceId=job_name, ResourceType="JOB"))
    assert (code_real, msg_real) == expected, (
        f"GetDashboardUrl on a real job gave {(code_real, msg_real)!r}, expected {expected!r}"
    )

    # the refusal is about the resource type, not a lookup: a job name that was never
    # created is refused identically rather than with a not-found error
    missing_job_name = ctx.unique_name("sim2real-behav-dash-missing-")
    code_missing, msg_missing = _error(
        lambda: glue.get_dashboard_url(ResourceId=missing_job_name, ResourceType="JOB")
    )
    assert (code_missing, msg_missing) == expected, (
        f"GetDashboardUrl on an unknown job gave {(code_missing, msg_missing)!r}, expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
